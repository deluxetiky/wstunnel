use super::types::RestrictionsRules;
use crate::restrictions::config_reloader::RestrictionsRulesReloaderState::{Config, Static};
use anyhow::Context;
use arc_swap::ArcSwap;
use log::trace;
use notify::{RecommendedWatcher, Watcher};
use parking_lot::Mutex;
use std::path::PathBuf;
use std::sync::Arc;
use tracing::{error, info};

struct ConfigReloaderState {
    fs_watcher: Mutex<RecommendedWatcher>,
    config_path: PathBuf,
}

#[derive(Clone)]
enum RestrictionsRulesReloaderState {
    Static,
    Config(Arc<ConfigReloaderState>),
}

#[derive(Clone)]
pub struct RestrictionsRulesReloader {
    state: RestrictionsRulesReloaderState,
    restrictions: Arc<ArcSwap<RestrictionsRules>>,
}

impl RestrictionsRulesReloader {
    pub fn new(restrictions_rules: RestrictionsRules, config_path: Option<PathBuf>) -> anyhow::Result<Self> {
        // If there is no custom certificate and private key, there is nothing to watch
        let config_path = if let Some(config_path) = config_path {
            if config_path.is_absolute() {
                config_path
            } else {
                std::env::current_dir()?.join(config_path)
            }
        } else {
            return Ok(Self {
                state: Static,
                restrictions: Arc::new(ArcSwap::from_pointee(restrictions_rules)),
            });
        };
        let reloader = Self {
            state: Config(Arc::new(ConfigReloaderState {
                fs_watcher: Mutex::new(notify::recommended_watcher(|_| {})?),
                config_path,
            })),
            restrictions: Arc::new(ArcSwap::from_pointee(restrictions_rules)),
        };

        info!("Starting to watch restriction config file for changes to reload them");
        let mut watcher = notify::recommended_watcher({
            let reloader = reloader.clone();

            move |event: notify::Result<notify::Event>| Self::handle_config_fs_event(&reloader, event)
        })
        .with_context(|| "Cannot create restriction config watcher")?;

        match &reloader.state {
            Static => {}
            Config(cfg) => {
                let parent = cfg.config_path.parent().unwrap_or(&cfg.config_path);
                watcher.watch(parent, notify::RecursiveMode::NonRecursive)?;
                *cfg.fs_watcher.lock() = watcher
            }
        }

        Ok(reloader)
    }

    pub fn reload_restrictions_config(&self) {
        let restrictions = match &self.state {
            Static => return,
            Config(st) => match RestrictionsRules::from_config_file(&st.config_path) {
                Ok(restrictions) => {
                    info!("Restrictions config file has been reloaded");
                    restrictions
                }
                Err(err) => {
                    error!("Cannot reload restrictions config file, keeping the old one. Error: {:?}", err);
                    return;
                }
            },
        };

        self.restrictions.store(Arc::new(restrictions));
    }

    pub const fn restrictions_rules(&self) -> &Arc<ArcSwap<RestrictionsRules>> {
        &self.restrictions
    }

    fn handle_config_fs_event(reloader: &RestrictionsRulesReloader, event: notify::Result<notify::Event>) {
        let this = match &reloader.state {
            Static => return,
            Config(st) => st,
        };

        let event = match event {
            Ok(event) => event,
            Err(err) => {
                error!("Error while watching restrictions config file for changes {:?}", err);
                return;
            }
        };

        if event.kind.is_access() {
            return;
        }

        trace!("Received event: {event:#?}");
        if event.paths.iter().any(|p| p.ends_with(&this.config_path)) {
            reloader.reload_restrictions_config();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs::File;
    use std::io::Write;
    use std::thread;
    use std::time::Duration;

    #[test]
    fn test_reload_config() -> anyhow::Result<()> {
        let temp_dir = std::env::temp_dir();
        let config_name = format!("wstunnel_test_config_{}.yaml", uuid::Uuid::new_v4());
        let real_path = temp_dir.join(&config_name);
        let link_path = temp_dir.join(format!("link_{}", config_name));

        let config1 = r#"
    restrictions:
      - name: "Allow all"
        match:
          - !Any
        allow:
          - !Tunnel
    "#;
        {
            let mut file = File::create(&real_path)?;
            write!(file, "{}", config1)?;
        }

        #[cfg(unix)]
        std::os::unix::fs::symlink(&real_path, &link_path)?;
        #[cfg(windows)]
        std::os::windows::fs::symlink_file(&real_path, &link_path)?;

        let reloader =
            RestrictionsRulesReloader::new(RestrictionsRules::from_config_file(&link_path)?, Some(link_path.clone()))?;

        // Verify initial config
        {
            let restrictions = reloader.restrictions_rules().load();
            assert_eq!(restrictions.restrictions.len(), 1);
            assert_eq!(restrictions.restrictions[0].name, "Allow all");
        }

        let config2 = r#"
    restrictions:
      - name: "Deny all"
        match:
          - !Any
        allow: []
    "#;

        thread::sleep(Duration::from_millis(100));

        let real_path_2 = temp_dir.join(format!("2_{}", config_name));
        {
            let mut file = File::create(&real_path_2)?;
            write!(file, "{}", config2)?;
            file.sync_all()?;
        }

        let temp_link_path = temp_dir.join(format!("temp_link_{}", config_name));
        #[cfg(unix)]
        std::os::unix::fs::symlink(&real_path_2, &temp_link_path)?;
        #[cfg(windows)]
        std::os::windows::fs::symlink_file(&real_path_2, &temp_link_path)?;

        std::fs::rename(&temp_link_path, &link_path)?;

        // Wait for reload
        let mut reloaded = false;
        for _ in 0..50 {
            thread::sleep(Duration::from_millis(100));
            let restrictions = reloader.restrictions_rules().load();
            if restrictions.restrictions[0].name == "Deny all" {
                reloaded = true;
                break;
            }
        }

        let _ = std::fs::remove_file(&link_path);
        let _ = std::fs::remove_file(&real_path);
        let _ = std::fs::remove_file(&real_path_2);
        assert!(reloaded, "Configuration was not reloaded");

        Ok(())
    }
}
