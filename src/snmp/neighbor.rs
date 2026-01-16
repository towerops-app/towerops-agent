use super::client::SnmpClient;
use super::types::{SnmpResult, SnmpValue};
use crate::metrics::{NeighborDiscovery, Timestamp};
use std::collections::HashMap;

/// LLDP-MIB remote table base OID
const LLDP_REM_TABLE_OID: &str = "1.0.8802.1.1.2.1.4.1.1";

/// CISCO-CDP-MIB neighbor table base OID
const CDP_CACHE_TABLE_OID: &str = "1.3.6.1.4.1.9.9.23.1.2.1.1";

/// Discover neighbors using LLDP and CDP
pub async fn discover_neighbors(
    client: &SnmpClient,
    ip_address: &str,
    community: &str,
    version: &str,
    port: u16,
    interfaces: &[(String, u32)], // (interface_id, if_index) pairs
) -> Vec<NeighborDiscovery> {
    let mut neighbors = Vec::new();

    // Discover LLDP neighbors
    if let Ok(lldp_neighbors) =
        discover_lldp_neighbors(client, ip_address, community, version, port, interfaces).await
    {
        neighbors.extend(lldp_neighbors);
    }

    // Discover CDP neighbors
    if let Ok(cdp_neighbors) =
        discover_cdp_neighbors(client, ip_address, community, version, port, interfaces).await
    {
        neighbors.extend(cdp_neighbors);
    }

    neighbors
}

/// Discover LLDP neighbors
async fn discover_lldp_neighbors(
    client: &SnmpClient,
    ip_address: &str,
    community: &str,
    version: &str,
    port: u16,
    interfaces: &[(String, u32)],
) -> SnmpResult<Vec<NeighborDiscovery>> {
    let entries = client
        .walk(ip_address, community, version, port, LLDP_REM_TABLE_OID)
        .await?;

    if entries.is_empty() {
        return Ok(Vec::new());
    }

    // Group entries by neighbor key (timemark.local_port_num.index)
    let mut neighbors_map: HashMap<String, HashMap<String, String>> = HashMap::new();

    for (oid, value) in entries {
        if let Some(neighbor_key) = extract_lldp_neighbor_key(&oid) {
            let field_name = extract_lldp_field_name(&oid);
            let value_str = snmp_value_to_string(value);

            neighbors_map
                .entry(neighbor_key)
                .or_default()
                .insert(field_name, value_str);
        }
    }

    // Convert to NeighborDiscovery structs
    let mut neighbors = Vec::new();
    for (_key, fields) in neighbors_map {
        if let Some(neighbor) = build_lldp_neighbor(fields, interfaces) {
            neighbors.push(neighbor);
        }
    }

    Ok(neighbors)
}

/// Discover CDP neighbors
async fn discover_cdp_neighbors(
    client: &SnmpClient,
    ip_address: &str,
    community: &str,
    version: &str,
    port: u16,
    interfaces: &[(String, u32)],
) -> SnmpResult<Vec<NeighborDiscovery>> {
    let entries = client
        .walk(ip_address, community, version, port, CDP_CACHE_TABLE_OID)
        .await?;

    if entries.is_empty() {
        return Ok(Vec::new());
    }

    // Group entries by neighbor key (if_index.device_index)
    let mut neighbors_map: HashMap<String, HashMap<String, String>> = HashMap::new();

    for (oid, value) in entries {
        if let Some(neighbor_key) = extract_cdp_neighbor_key(&oid) {
            let field_name = extract_cdp_field_name(&oid);
            let value_str = snmp_value_to_string(value);

            neighbors_map
                .entry(neighbor_key)
                .or_default()
                .insert(field_name, value_str);
        }
    }

    // Convert to NeighborDiscovery structs
    let mut neighbors = Vec::new();
    for (_key, fields) in neighbors_map {
        if let Some(neighbor) = build_cdp_neighbor(fields, interfaces) {
            neighbors.push(neighbor);
        }
    }

    Ok(neighbors)
}

/// Extract neighbor key from LLDP OID (timemark.local_port_num.index)
fn extract_lldp_neighbor_key(oid: &str) -> Option<String> {
    // OID format: 1.0.8802.1.1.2.1.4.1.1.X.timemark.local_port_num.index
    let parts: Vec<&str> = oid.split('.').collect();
    if parts.len() >= 14 {
        // Extract last 3 parts as neighbor key
        Some(parts[parts.len() - 3..].join("."))
    } else {
        None
    }
}

/// Extract field name from LLDP OID
fn extract_lldp_field_name(oid: &str) -> String {
    // OID format: 1.0.8802.1.1.2.1.4.1.1.X.timemark.local_port_num.index
    // X is the field identifier
    let parts: Vec<&str> = oid.split('.').collect();
    if parts.len() >= 11 {
        parts[10].to_string()
    } else {
        "unknown".to_string()
    }
}

/// Extract neighbor key from CDP OID (if_index.device_index)
fn extract_cdp_neighbor_key(oid: &str) -> Option<String> {
    // OID format: 1.3.6.1.4.1.9.9.23.1.2.1.1.X.if_index.device_index
    let parts: Vec<&str> = oid.split('.').collect();
    if parts.len() >= 13 {
        // Extract last 2 parts as neighbor key
        Some(parts[parts.len() - 2..].join("."))
    } else {
        None
    }
}

/// Extract field name from CDP OID
fn extract_cdp_field_name(oid: &str) -> String {
    // OID format: 1.3.6.1.4.1.9.9.23.1.2.1.1.X.if_index.device_index
    // X is the field identifier
    let parts: Vec<&str> = oid.split('.').collect();
    if parts.len() >= 11 {
        parts[10].to_string()
    } else {
        "unknown".to_string()
    }
}

/// Convert SnmpValue to string
fn snmp_value_to_string(value: SnmpValue) -> String {
    match value {
        SnmpValue::String(s) => s,
        SnmpValue::Integer(i) => i.to_string(),
        SnmpValue::Counter32(c) => c.to_string(),
        SnmpValue::Counter64(c) => c.to_string(),
        SnmpValue::Gauge32(g) => g.to_string(),
        SnmpValue::TimeTicks(t) => t.to_string(),
        SnmpValue::IpAddress(ip) => ip,
    }
}

/// Build LLDP neighbor from fields
fn build_lldp_neighbor(
    fields: HashMap<String, String>,
    interfaces: &[(String, u32)],
) -> Option<NeighborDiscovery> {
    // Field IDs from LLDP-MIB
    // 4 = lldpRemChassisIdSubtype
    // 5 = lldpRemChassisId
    // 6 = lldpRemPortIdSubtype
    // 7 = lldpRemPortId
    // 8 = lldpRemPortDesc
    // 9 = lldpRemSysName
    // 10 = lldpRemSysDesc
    // 12 = lldpRemManAddr

    let local_port_num = fields.get("local_port_num")?;
    let if_index: u32 = local_port_num.parse().ok()?;

    let interface_id = interfaces
        .iter()
        .find(|(_, idx)| *idx == if_index)
        .map(|(id, _)| id.clone())?;

    let remote_chassis_id = fields.get("5").cloned().unwrap_or_default();
    let remote_system_name = fields.get("9").cloned().unwrap_or_default();
    let remote_system_description = fields.get("10").cloned().unwrap_or_default();
    let remote_port_id = fields.get("7").cloned().unwrap_or_default();
    let remote_port_description = fields.get("8").cloned().unwrap_or_default();
    let remote_address = fields.get("12").cloned().unwrap_or_default();

    // Parse capabilities (if available)
    let remote_capabilities = Vec::new(); // TODO: Parse from lldpRemSysCapEnabled

    Some(NeighborDiscovery {
        interface_id,
        protocol: "lldp".to_string(),
        remote_chassis_id,
        remote_system_name,
        remote_system_description,
        remote_platform: String::new(),
        remote_port_id,
        remote_port_description,
        remote_address,
        remote_capabilities,
        timestamp: Timestamp::now(),
    })
}

/// Build CDP neighbor from fields
fn build_cdp_neighbor(
    fields: HashMap<String, String>,
    interfaces: &[(String, u32)],
) -> Option<NeighborDiscovery> {
    // Field IDs from CISCO-CDP-MIB
    // 4 = cdpCacheAddressType
    // 5 = cdpCacheAddress
    // 6 = cdpCacheVersion
    // 7 = cdpCacheDeviceId
    // 8 = cdpCacheDevicePort
    // 9 = cdpCachePlatform
    // 10 = cdpCacheCapabilities

    let if_index_str = fields.get("if_index")?;
    let if_index: u32 = if_index_str.parse().ok()?;

    let interface_id = interfaces
        .iter()
        .find(|(_, idx)| *idx == if_index)
        .map(|(id, _)| id.clone())?;

    let remote_chassis_id = fields.get("7").cloned().unwrap_or_default();
    let remote_system_name = remote_chassis_id.clone();
    let remote_system_description = fields.get("6").cloned().unwrap_or_default();
    let remote_platform = fields.get("9").cloned().unwrap_or_default();
    let remote_port_id = fields.get("8").cloned().unwrap_or_default();
    let remote_address = fields.get("5").cloned().unwrap_or_default();

    // Parse capabilities (if available)
    let remote_capabilities = Vec::new(); // TODO: Parse from cdpCacheCapabilities

    Some(NeighborDiscovery {
        interface_id,
        protocol: "cdp".to_string(),
        remote_chassis_id,
        remote_system_name,
        remote_system_description,
        remote_platform,
        remote_port_id,
        remote_port_description: String::new(),
        remote_address,
        remote_capabilities,
        timestamp: Timestamp::now(),
    })
}
