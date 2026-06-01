// Copyright 2019-2024 Tauri Programme within The Commons Conservancy
// SPDX-License-Identifier: Apache-2.0
// SPDX-License-Identifier: MIT

//! macOS App Sandbox support for `tauri dev`.
//!
//! Everything in this module is macOS-only. It builds the dev binary, wraps it in a minimal
//! signed `.app` bundle with the configured entitlements, and launches it so `tauri dev`
//! enforces the same sandbox restrictions as a release build. None of this is referenced from
//! cross-platform code: the `bundle > macOS > sandbox` config value is read only here.

use std::{
  fs,
  io::ErrorKind,
  path::{Path, PathBuf},
  process::Command,
  sync::{atomic::AtomicBool, Arc},
};

use shared_child::SharedChild;

use super::super::{AppSettings, ExitReason, Options, Rust};
use super::{cargo_command, spawn_dev_process, DevChild};
use crate::{
  error::{Context, ErrorExt},
  helpers::{app_paths::Dirs, config::ConfigMetadata},
  CommandExt, Error,
};

/// Configuration required to wrap the dev binary in a signed `.app` bundle so that
/// `tauri dev` runs under the macOS App Sandbox.
#[derive(Debug, Clone)]
struct MacosSandboxConfig {
  /// Path to the compiled dev binary.
  binary_path: PathBuf,
  /// Directory where the dev `.app` bundle is written.
  bundle_dir: PathBuf,
  /// Product name used for the `.app` bundle.
  product_name: String,
  /// Bundle identifier (`CFBundleIdentifier`).
  bundle_identifier: String,
  /// Bundle version (`CFBundleShortVersionString` / `CFBundleVersion`).
  bundle_version: String,
  /// Minimum macOS system version, used for both the build and the `Info.plist`.
  minimum_system_version: Option<String>,
  /// Path to the entitlements file applied during code signing.
  entitlements: Option<PathBuf>,
  /// Signing identity to use. `None` means an ad-hoc signature (`codesign -s -`).
  signing_identity: Option<String>,
  /// Whether to enable the hardened runtime when signing.
  hardened_runtime: bool,
  /// Bundle resources (`bundle > resources`) to copy into `Contents/Resources`,
  /// so `resource_dir()` resolves the same way it does for a release `.app`.
  resources: Option<tauri_utils::config::BundleResources>,
  /// The tauri directory (e.g. `src-tauri`), used to resolve relative resource
  /// patterns the same way the real bundler does.
  tauri_dir: PathBuf,
}

/// Builds the dev binary, wraps it in a minimal signed `.app` bundle and launches it so the
/// app runs under the macOS App Sandbox using the configured entitlements.
///
/// Called only when the sandbox is enabled for this dev session (see the dispatch in
/// `Rust::run_dev_dispatch`).
pub fn run_dev<F: Fn(Option<i32>, ExitReason) + Send + Sync + 'static>(
  rust: &mut Rust,
  options: Options,
  run_args: &[String],
  config: &ConfigMetadata,
  dirs: &Dirs,
  on_exit: F,
) -> crate::Result<DevChild> {
  let sandbox = resolve(rust, &options, config, dirs)?;

  // Mirror release builds: set the deployment target so the dev build matches the bundle.
  if let Some(minimum_system_version) = &sandbox.minimum_system_version {
    std::env::set_var("MACOSX_DEPLOYMENT_TARGET", minimum_system_version);
  }

  // Build (instead of `cargo run`) so we can post-process the binary before launching it.
  let mut build_cmd = cargo_command(
    false,
    options,
    &mut rust.available_targets,
    rust.config_features.clone(),
  )?;
  let runner = build_cmd.get_program().to_string_lossy().into_owned();
  log::info!(action = "Building"; "sandboxed dev app");
  let build_status = match build_cmd.piped() {
    Ok(status) => status,
    Err(e) if e.kind() == ErrorKind::NotFound => crate::error::bail!(
      "`{runner}` command not found.{}",
      if runner == "cargo" {
        " Please follow the Tauri setup guide: https://v2.tauri.app/start/prerequisites/"
      } else {
        ""
      }
    ),
    Err(e) => {
      return Err(Error::CommandFailed {
        command: runner,
        error: e,
      })
    }
  };

  if !build_status.success() {
    // Keep the watcher alive (CompilationFailed neither exits nor counts as a kill).
    on_exit(build_status.code(), ExitReason::CompilationFailed);
    return finished_dev_child();
  }

  let executable = match bundle_and_sign_dev_app(&sandbox) {
    Ok(path) => path,
    Err(e) => {
      log::error!("failed to prepare sandboxed dev app: {e}");
      on_exit(None, ExitReason::CompilationFailed);
      return finished_dev_child();
    }
  };

  let mut app_cmd = Command::new(&executable);
  app_cmd.args(run_args);
  spawn_dev_process(app_cmd, on_exit)
}

/// Resolves the macOS App Sandbox configuration for a dev session from the app settings and
/// the (possibly reloaded) Tauri configuration.
fn resolve(
  rust: &Rust,
  options: &Options,
  config: &ConfigMetadata,
  dirs: &Dirs,
) -> crate::Result<MacosSandboxConfig> {
  let tauri_dir = dirs.tauri;
  let binary_path = rust.app_settings.app_binary_path(options, tauri_dir)?;
  let product_name = config.product_name.clone().unwrap_or_else(|| {
    binary_path
      .file_stem()
      .map(|s| s.to_string_lossy().into_owned())
      .unwrap_or_else(|| "App".to_string())
  });
  let bundle_dir = rust
    .app_settings
    .out_dir(options, tauri_dir)?
    .join("tauri-dev-sandbox");

  let entitlements = config
    .bundle
    .macos
    .entitlements
    .as_ref()
    .map(|p| tauri_dir.join(p));
  if entitlements.is_none() {
    log::warn!(
      "macOS dev sandbox is enabled but no `bundle > macOS > entitlements` file is configured; the app will be signed without sandbox entitlements and will not be sandboxed."
    );
  }

  let signing_identity = std::env::var("APPLE_SIGNING_IDENTITY")
    .ok()
    .or_else(|| config.bundle.macos.signing_identity.clone());

  Ok(MacosSandboxConfig {
    binary_path,
    bundle_dir,
    product_name,
    bundle_identifier: config.identifier.clone(),
    bundle_version: config
      .version
      .clone()
      .unwrap_or_else(|| "0.0.0".to_string()),
    minimum_system_version: config.bundle.macos.minimum_system_version.clone(),
    entitlements,
    signing_identity,
    hardened_runtime: config.bundle.macos.hardened_runtime,
    resources: config.bundle.resources.clone(),
    tauri_dir: tauri_dir.to_path_buf(),
  })
}

/// Returns a `DevChild` wrapping an already-finished process, used when a sandboxed build or
/// signing step fails so the file watcher can keep running without a live app process.
fn finished_dev_child() -> crate::Result<DevChild> {
  let mut placeholder = Command::new("true");
  let child = SharedChild::spawn(&mut placeholder).map_err(|error| Error::CommandFailed {
    command: "true".to_string(),
    error,
  })?;

  Ok(DevChild {
    manually_killed_app: Arc::new(AtomicBool::default()),
    dev_child: Arc::new(child),
  })
}

/// Wraps the built binary in a minimal `.app` bundle and code signs it (ad-hoc by default)
/// with the configured entitlements. Returns the path to the bundled executable to launch.
fn bundle_and_sign_dev_app(sandbox: &MacosSandboxConfig) -> crate::Result<PathBuf> {
  let app_path = sandbox
    .bundle_dir
    .join(format!("{}.app", sandbox.product_name));

  // Rebuild the bundle from scratch each time so stale artifacts/signatures never linger.
  if app_path.exists() {
    fs::remove_dir_all(&app_path).fs_context("failed to clean dev sandbox app", app_path.clone())?;
  }

  let contents_dir = app_path.join("Contents");
  let macos_dir = contents_dir.join("MacOS");
  fs::create_dir_all(&macos_dir).fs_context("failed to create dev sandbox app", macos_dir.clone())?;

  let bin_file_name = sandbox
    .binary_path
    .file_name()
    .context("dev binary has no file name")?;
  let dest_binary = macos_dir.join(bin_file_name);
  fs::copy(&sandbox.binary_path, &dest_binary)
    .fs_context("failed to copy dev binary into sandbox app", dest_binary.clone())?;

  create_dev_info_plist(&contents_dir, &bin_file_name.to_string_lossy(), sandbox)?;

  // Populate `Contents/Resources` so `resource_dir()` resolves to a real directory
  // containing the bundled resources. Without this the binary runs from inside a
  // `.app`, so Tauri's dev cargo-output detection no longer applies and
  // `resource_dir()` points at the (otherwise missing) `Contents/Resources`.
  copy_dev_resources(&contents_dir.join("Resources"), sandbox)?;

  let identity = sandbox
    .signing_identity
    .clone()
    .unwrap_or_else(|| "-".to_string());
  if identity == "-" {
    log::info!(action = "Signing"; "dev sandbox app with an ad-hoc signature");
  }
  let keychain = tauri_macos_sign::Keychain::with_signing_identity(identity);
  keychain
    .sign(
      &app_path,
      sandbox.entitlements.as_deref(),
      sandbox.hardened_runtime,
    )
    .map_err(Box::new)?;

  Ok(dest_binary)
}

/// Copies the configured `bundle > resources` into the dev sandbox app's
/// `Contents/Resources` directory, mirroring how `tauri build` lays out a
/// release `.app`. Resource patterns are resolved relative to the tauri
/// directory so glob/walk matching works regardless of the process cwd.
fn copy_dev_resources(resources_dir: &Path, sandbox: &MacosSandboxConfig) -> crate::Result<()> {
  use std::collections::HashMap;
  use tauri_utils::{config::BundleResources, resources::ResourcePaths};

  let Some(resources) = &sandbox.resources else {
    return Ok(());
  };

  // Resolve a pattern relative to the tauri dir unless it is already absolute,
  // matching the real bundler which runs with the tauri dir as its cwd.
  let resolve = |pattern: &str| -> String {
    let path = Path::new(pattern);
    if path.is_absolute() {
      pattern.to_string()
    } else {
      sandbox.tauri_dir.join(path).to_string_lossy().into_owned()
    }
  };

  // Own absolute-source variants so glob/walk resolution does not depend on cwd.
  let list_owned: Option<Vec<String>> = match resources {
    BundleResources::List(list) => Some(list.iter().map(|p| resolve(p)).collect()),
    BundleResources::Map(_) => None,
  };
  let map_owned: Option<HashMap<String, String>> = match resources {
    BundleResources::Map(map) => Some(
      map
        .iter()
        .map(|(src, dest)| (resolve(src), dest.clone()))
        .collect(),
    ),
    BundleResources::List(_) => None,
  };

  let resource_paths = match (&list_owned, &map_owned) {
    (Some(list), None) => ResourcePaths::new(list.as_slice(), true),
    (None, Some(map)) => ResourcePaths::from_map(map, true),
    // `BundleResources` is one variant or the other, so the remaining arms are unreachable.
    _ => return Ok(()),
  };

  for resource in resource_paths.iter() {
    let resource = resource.context("failed to resolve dev sandbox resource")?;
    let dest = resources_dir.join(resource.target());
    if let Some(parent) = dest.parent() {
      fs::create_dir_all(parent)
        .fs_context("failed to create dev sandbox resource directory", parent.to_path_buf())?;
    }
    fs::copy(resource.path(), &dest)
      .fs_context("failed to copy dev sandbox resource", dest.clone())?;
  }

  Ok(())
}

/// Writes a minimal `Info.plist` for the dev sandbox `.app` bundle.
fn create_dev_info_plist(
  contents_dir: &Path,
  executable: &str,
  sandbox: &MacosSandboxConfig,
) -> crate::Result<()> {
  let mut plist = plist::Dictionary::new();
  plist.insert("CFBundleDevelopmentRegion".into(), "English".into());
  plist.insert(
    "CFBundleDisplayName".into(),
    sandbox.product_name.clone().into(),
  );
  plist.insert("CFBundleExecutable".into(), executable.into());
  plist.insert(
    "CFBundleIdentifier".into(),
    sandbox.bundle_identifier.clone().into(),
  );
  plist.insert("CFBundleInfoDictionaryVersion".into(), "6.0".into());
  plist.insert("CFBundleName".into(), sandbox.product_name.clone().into());
  plist.insert("CFBundlePackageType".into(), "APPL".into());
  plist.insert(
    "CFBundleShortVersionString".into(),
    sandbox.bundle_version.clone().into(),
  );
  plist.insert(
    "CFBundleVersion".into(),
    sandbox.bundle_version.clone().into(),
  );
  if let Some(minimum_system_version) = &sandbox.minimum_system_version {
    plist.insert(
      "LSMinimumSystemVersion".into(),
      minimum_system_version.clone().into(),
    );
  }
  plist.insert("NSHighResolutionCapable".into(), true.into());

  plist::Value::Dictionary(plist)
    .to_file_xml(contents_dir.join("Info.plist"))
    .map_err(|e| Error::GenericError(format!("failed to write dev sandbox Info.plist: {e}")))?;

  Ok(())
}
