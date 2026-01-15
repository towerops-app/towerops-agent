use crate::buffer::Storage;
use crate::buffer::StorageError;

#[derive(Debug)]
pub enum ExecutorError {
    Storage(StorageError),
    Snmp(crate::snmp::SnmpError),
    Conversion(String),
}

impl std::fmt::Display for ExecutorError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Storage(err) => write!(f, "Storage error: {}", err),
            Self::Snmp(err) => write!(f, "SNMP error: {}", err),
            Self::Conversion(msg) => write!(f, "Conversion error: {}", msg),
        }
    }
}

impl std::error::Error for ExecutorError {}

impl From<StorageError> for ExecutorError {
    fn from(err: StorageError) -> Self {
        Self::Storage(err)
    }
}

impl From<crate::snmp::SnmpError> for ExecutorError {
    fn from(err: crate::snmp::SnmpError) -> Self {
        Self::Snmp(err)
    }
}

pub type Result<T> = std::result::Result<T, ExecutorError>;

use crate::config::EquipmentConfig;
use crate::metrics::{InterfaceStat, Metric, SensorReading};
use crate::snmp::SnmpClient;

use crate::metrics::Timestamp;
use log::{error, info, warn};

/// Executor handles polling individual pieces of equipment
#[derive(Clone)]
pub struct Executor {
    snmp_client: SnmpClient,
    storage: Storage,
}

impl Executor {
    pub fn new(snmp_client: SnmpClient, storage: Storage) -> Self {
        Self {
            snmp_client,
            storage,
        }
    }

    /// Poll sensors for a piece of equipment
    pub async fn poll_sensors(&self, equipment: &EquipmentConfig) -> Result<()> {
        if !equipment.snmp.enabled || equipment.sensors.is_empty() {
            return Ok(());
        }

        info!(
            "Polling {} sensors for equipment: {}",
            equipment.sensors.len(),
            equipment.name
        );

        for sensor in &equipment.sensors {
            match self
                .snmp_client
                .get(
                    &equipment.ip_address,
                    &equipment.snmp.community,
                    &equipment.snmp.version,
                    equipment.snmp.port,
                    &sensor.oid,
                )
                .await
            {
                Ok(value) => {
                    let raw_value = match value.as_f64() {
                        Some(v) => v,
                        None => {
                            warn!(
                                "Could not convert sensor value to number for sensor {}",
                                sensor.id
                            );
                            continue;
                        }
                    };

                    // Apply divisor if specified
                    let final_value = if let Some(divisor) = sensor.divisor {
                        if divisor != 0 {
                            raw_value / divisor as f64
                        } else {
                            raw_value
                        }
                    } else {
                        raw_value
                    };

                    let reading = SensorReading {
                        sensor_id: sensor.id.clone(),
                        value: final_value,
                        status: "ok".to_string(),
                        timestamp: Timestamp::now(),
                    };

                    if let Err(e) = self.storage.store_metric(&Metric::SensorReading(reading)) {
                        error!("Failed to store sensor reading: {}", e);
                    }
                }
                Err(e) => {
                    warn!(
                        "Failed to poll sensor {} for {}: {}",
                        sensor.oid, equipment.name, e
                    );
                }
            }
        }

        Ok(())
    }

    /// Poll interfaces for a piece of equipment
    pub async fn poll_interfaces(&self, equipment: &EquipmentConfig) -> Result<()> {
        if !equipment.snmp.enabled || equipment.interfaces.is_empty() {
            return Ok(());
        }

        info!(
            "Polling {} interfaces for equipment: {}",
            equipment.interfaces.len(),
            equipment.name
        );

        for interface in &equipment.interfaces {
            // OIDs for interface statistics (from IF-MIB)
            let if_in_octets_oid = format!("1.3.6.1.2.1.2.2.1.10.{}", interface.if_index);
            let if_out_octets_oid = format!("1.3.6.1.2.1.2.2.1.16.{}", interface.if_index);
            let if_in_errors_oid = format!("1.3.6.1.2.1.2.2.1.14.{}", interface.if_index);
            let if_out_errors_oid = format!("1.3.6.1.2.1.2.2.1.20.{}", interface.if_index);
            let if_in_discards_oid = format!("1.3.6.1.2.1.2.2.1.13.{}", interface.if_index);
            let if_out_discards_oid = format!("1.3.6.1.2.1.2.2.1.19.{}", interface.if_index);

            // Poll each counter
            let in_octets = self
                .get_counter(
                    &equipment.ip_address,
                    &equipment.snmp.community,
                    &equipment.snmp.version,
                    equipment.snmp.port,
                    &if_in_octets_oid,
                )
                .await
                .unwrap_or(0);

            let out_octets = self
                .get_counter(
                    &equipment.ip_address,
                    &equipment.snmp.community,
                    &equipment.snmp.version,
                    equipment.snmp.port,
                    &if_out_octets_oid,
                )
                .await
                .unwrap_or(0);

            let in_errors = self
                .get_counter(
                    &equipment.ip_address,
                    &equipment.snmp.community,
                    &equipment.snmp.version,
                    equipment.snmp.port,
                    &if_in_errors_oid,
                )
                .await
                .unwrap_or(0);

            let out_errors = self
                .get_counter(
                    &equipment.ip_address,
                    &equipment.snmp.community,
                    &equipment.snmp.version,
                    equipment.snmp.port,
                    &if_out_errors_oid,
                )
                .await
                .unwrap_or(0);

            let in_discards = self
                .get_counter(
                    &equipment.ip_address,
                    &equipment.snmp.community,
                    &equipment.snmp.version,
                    equipment.snmp.port,
                    &if_in_discards_oid,
                )
                .await
                .unwrap_or(0);

            let out_discards = self
                .get_counter(
                    &equipment.ip_address,
                    &equipment.snmp.community,
                    &equipment.snmp.version,
                    equipment.snmp.port,
                    &if_out_discards_oid,
                )
                .await
                .unwrap_or(0);

            let stat = InterfaceStat {
                interface_id: interface.id.clone(),
                if_in_octets: in_octets,
                if_out_octets: out_octets,
                if_in_errors: in_errors,
                if_out_errors: out_errors,
                if_in_discards: in_discards,
                if_out_discards: out_discards,
                timestamp: Timestamp::now(),
            };

            if let Err(e) = self.storage.store_metric(&Metric::InterfaceStat(stat)) {
                error!("Failed to store interface stat: {}", e);
            }
        }

        Ok(())
    }

    async fn get_counter(
        &self,
        ip_address: &str,
        community: &str,
        version: &str,
        port: u16,
        oid: &str,
    ) -> Result<i64> {
        let value = self
            .snmp_client
            .get(ip_address, community, version, port, oid)
            .await?;

        value
            .as_i64()
            .ok_or_else(|| ExecutorError::Conversion("Could not convert value to i64".into()))
    }
}
