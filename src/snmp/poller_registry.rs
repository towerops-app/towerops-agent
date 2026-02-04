use super::device_poller::{DeviceConfig, DevicePoller};
use std::collections::HashMap;
use std::sync::{Arc, RwLock};

/// Registry of active device pollers
#[derive(Clone)]
pub struct PollerRegistry {
    pollers: Arc<RwLock<HashMap<String, Arc<DevicePoller>>>>,
}

impl PollerRegistry {
    /// Create a new poller registry
    pub fn new() -> Self {
        Self {
            pollers: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    /// Get or create a device poller
    pub fn get_or_create(&self, device_id: String, config: DeviceConfig) -> Arc<DevicePoller> {
        // Try read lock first (fast path if poller exists)
        {
            let pollers = self.pollers.read().unwrap();
            if let Some(poller) = pollers.get(&device_id) {
                poller.log_status();
                return Arc::clone(poller);
            }
        }

        // Need to create new poller (write lock)
        let mut pollers = self.pollers.write().unwrap();

        // Double-check in case another thread created it while we waited for write lock
        if let Some(poller) = pollers.get(&device_id) {
            poller.log_status();
            return Arc::clone(poller);
        }

        // Create new poller
        let poller = Arc::new(DevicePoller::spawn(device_id.clone(), config));
        pollers.insert(device_id, Arc::clone(&poller));

        // Release write lock before logging
        drop(pollers);

        tracing::info!("Created new device poller (total: {})", self.count());
        poller.log_status();

        poller
    }

    /// Remove a device poller (shutdown thread)
    /// Called when a device is deleted or no longer needs polling
    pub fn remove(&self, device_id: &str) {
        let mut pollers = self.pollers.write().unwrap();
        if let Some(poller) = pollers.remove(device_id) {
            poller.shutdown();
            tracing::info!(
                "Removed device poller for {} (remaining: {})",
                device_id,
                pollers.len()
            );
        }
    }

    /// Get a list of active device IDs
    pub fn list_devices(&self) -> Vec<String> {
        let pollers = self.pollers.read().unwrap();
        pollers.keys().cloned().collect()
    }

    /// Get count of active pollers
    pub fn count(&self) -> usize {
        let pollers = self.pollers.read().unwrap();
        pollers.len()
    }

    /// Shutdown all pollers
    pub fn shutdown_all(&self) {
        let device_list = self.list_devices();
        if !device_list.is_empty() {
            tracing::info!("Shutting down {} device pollers", device_list.len());
        }

        let mut pollers = self.pollers.write().unwrap();
        for (device_id, poller) in pollers.drain() {
            poller.shutdown();
            tracing::debug!("Shutdown device poller for {}", device_id);
        }
    }
}

impl Default for PollerRegistry {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::secret::SecretString;

    #[test]
    fn test_registry_remove() {
        let registry = PollerRegistry::new();

        // Create a test device config
        let config = DeviceConfig {
            ip: "127.0.0.1".to_string(),
            port: 161,
            version: "2c".to_string(),
            community: SecretString::new("public"),
            v3_config: None,
            transport: "udp".to_string(),
        };

        // Create a poller
        let poller = registry.get_or_create("test-device".to_string(), config);
        assert_eq!(registry.count(), 1);
        assert_eq!(poller.device_id(), "test-device");

        // Remove the poller
        registry.remove("test-device");
        assert_eq!(registry.count(), 0);
    }

    #[test]
    fn test_device_poller_accessors() {
        let config = DeviceConfig {
            ip: "192.168.1.1".to_string(),
            port: 161,
            version: "2c".to_string(),
            community: SecretString::new("public"),
            v3_config: None,
            transport: "udp".to_string(),
        };

        let poller = DevicePoller::spawn("test-device".to_string(), config.clone());

        // Test accessors
        assert_eq!(poller.device_id(), "test-device");
        assert_eq!(poller.config().ip, "192.168.1.1");
        assert_eq!(poller.config().port, 161);

        poller.shutdown();
    }
}
