use std::env;
use std::path::PathBuf;

// This stores the superset of environment-backed directory hints so the
// platform-specific resolvers can share one testable input shape.
#[allow(dead_code)]
#[derive(Debug, Clone, Default)]
struct PlatformEnv {
    home: Option<PathBuf>,
    xdg_data_home: Option<PathBuf>,
    xdg_config_home: Option<PathBuf>,
    xdg_cache_home: Option<PathBuf>,
    appdata: Option<PathBuf>,
    localappdata: Option<PathBuf>,
}

pub(crate) fn app_data_dir(app_name: &str) -> Option<PathBuf> {
    resolve_data_dir(&PlatformEnv::current()).map(|dir| dir.join(app_name))
}

pub(crate) fn app_config_dir(app_name: &str) -> Option<PathBuf> {
    resolve_config_dir(&PlatformEnv::current()).map(|dir| dir.join(app_name))
}

pub(crate) fn app_cache_dir(app_name: &str) -> Option<PathBuf> {
    resolve_cache_dir(&PlatformEnv::current()).map(|dir| dir.join(app_name))
}

impl PlatformEnv {
    fn current() -> Self {
        Self {
            home: home_dir(),
            xdg_data_home: env_path("XDG_DATA_HOME"),
            xdg_config_home: env_path("XDG_CONFIG_HOME"),
            xdg_cache_home: env_path("XDG_CACHE_HOME"),
            appdata: env_path("APPDATA"),
            localappdata: env_path("LOCALAPPDATA"),
        }
    }
}

fn env_path(name: &str) -> Option<PathBuf> {
    env::var_os(name).map(PathBuf::from)
}

#[cfg(windows)]
fn home_dir() -> Option<PathBuf> {
    env_path("USERPROFILE").or_else(|| {
        let home_drive = env::var_os("HOMEDRIVE")?;
        let home_path = env::var_os("HOMEPATH")?;
        let mut path = PathBuf::from(home_drive);
        path.push(home_path);
        Some(path)
    })
}

#[cfg(not(windows))]
fn home_dir() -> Option<PathBuf> {
    env_path("HOME")
}

#[cfg(windows)]
fn resolve_data_dir(env: &PlatformEnv) -> Option<PathBuf> {
    env.appdata.clone().or_else(|| {
        env.home
            .as_ref()
            .map(|home| home.join("AppData").join("Roaming"))
    })
}

#[cfg(target_os = "macos")]
fn resolve_data_dir(env: &PlatformEnv) -> Option<PathBuf> {
    env.home
        .as_ref()
        .map(|home| home.join("Library").join("Application Support"))
}

#[cfg(all(not(windows), not(target_os = "macos")))]
fn resolve_data_dir(env: &PlatformEnv) -> Option<PathBuf> {
    env.xdg_data_home.clone().or_else(|| {
        env.home
            .as_ref()
            .map(|home| home.join(".local").join("share"))
    })
}

#[cfg(windows)]
fn resolve_config_dir(env: &PlatformEnv) -> Option<PathBuf> {
    resolve_data_dir(env)
}

#[cfg(target_os = "macos")]
fn resolve_config_dir(env: &PlatformEnv) -> Option<PathBuf> {
    resolve_data_dir(env)
}

#[cfg(all(not(windows), not(target_os = "macos")))]
fn resolve_config_dir(env: &PlatformEnv) -> Option<PathBuf> {
    env.xdg_config_home
        .clone()
        .or_else(|| env.home.as_ref().map(|home| home.join(".config")))
}

#[cfg(windows)]
fn resolve_cache_dir(env: &PlatformEnv) -> Option<PathBuf> {
    env.localappdata.clone().or_else(|| {
        env.home
            .as_ref()
            .map(|home| home.join("AppData").join("Local"))
    })
}

#[cfg(target_os = "macos")]
fn resolve_cache_dir(env: &PlatformEnv) -> Option<PathBuf> {
    env.home
        .as_ref()
        .map(|home| home.join("Library").join("Caches"))
}

#[cfg(all(not(windows), not(target_os = "macos")))]
fn resolve_cache_dir(env: &PlatformEnv) -> Option<PathBuf> {
    env.xdg_cache_home
        .clone()
        .or_else(|| env.home.as_ref().map(|home| home.join(".cache")))
}

#[cfg(test)]
mod tests {
    use super::{resolve_cache_dir, resolve_config_dir, resolve_data_dir, PlatformEnv};
    use std::path::PathBuf;

    #[cfg(all(not(windows), not(target_os = "macos")))]
    #[test]
    fn unix_dirs_prefer_xdg_env_vars() {
        let env = PlatformEnv {
            home: Some(PathBuf::from("/home/tester")),
            xdg_data_home: Some(PathBuf::from("/tmp/data")),
            xdg_config_home: Some(PathBuf::from("/tmp/config")),
            xdg_cache_home: Some(PathBuf::from("/tmp/cache")),
            ..PlatformEnv::default()
        };

        assert_eq!(resolve_data_dir(&env), Some(PathBuf::from("/tmp/data")));
        assert_eq!(resolve_config_dir(&env), Some(PathBuf::from("/tmp/config")));
        assert_eq!(resolve_cache_dir(&env), Some(PathBuf::from("/tmp/cache")));
    }

    #[cfg(all(not(windows), not(target_os = "macos")))]
    #[test]
    fn unix_dirs_fall_back_to_home() {
        let env = PlatformEnv {
            home: Some(PathBuf::from("/home/tester")),
            ..PlatformEnv::default()
        };

        assert_eq!(
            resolve_data_dir(&env),
            Some(PathBuf::from("/home/tester/.local/share"))
        );
        assert_eq!(
            resolve_config_dir(&env),
            Some(PathBuf::from("/home/tester/.config"))
        );
        assert_eq!(
            resolve_cache_dir(&env),
            Some(PathBuf::from("/home/tester/.cache"))
        );
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn macos_dirs_use_library_conventions() {
        let env = PlatformEnv {
            home: Some(PathBuf::from("/Users/tester")),
            ..PlatformEnv::default()
        };

        assert_eq!(
            resolve_data_dir(&env),
            Some(PathBuf::from("/Users/tester/Library/Application Support"))
        );
        assert_eq!(
            resolve_config_dir(&env),
            Some(PathBuf::from("/Users/tester/Library/Application Support"))
        );
        assert_eq!(
            resolve_cache_dir(&env),
            Some(PathBuf::from("/Users/tester/Library/Caches"))
        );
    }

    #[cfg(windows)]
    #[test]
    fn windows_dirs_prefer_appdata() {
        let env = PlatformEnv {
            home: Some(PathBuf::from("C:/Users/tester")),
            appdata: Some(PathBuf::from("C:/Users/tester/AppData/Roaming")),
            localappdata: Some(PathBuf::from("C:/Users/tester/AppData/Local")),
            ..PlatformEnv::default()
        };

        assert_eq!(
            resolve_data_dir(&env),
            Some(PathBuf::from("C:/Users/tester/AppData/Roaming"))
        );
        assert_eq!(
            resolve_config_dir(&env),
            Some(PathBuf::from("C:/Users/tester/AppData/Roaming"))
        );
        assert_eq!(
            resolve_cache_dir(&env),
            Some(PathBuf::from("C:/Users/tester/AppData/Local"))
        );
    }
}
