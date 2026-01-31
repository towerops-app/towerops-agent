# SNMP Trap Listener Design

## Overview

Add SNMP trap listening capability to the towerops-agent. The agent will listen on UDP port 162 for incoming SNMP traps (both v1 and v2c formats) and log them at INFO level.

## Requirements

- Support both SNMPv1 and SNMPv2c trap formats
- Listen on UDP port 162 (standard SNMP trap port)
- Log received traps at INFO level
- Configurable log level via `LOG_LEVEL` environment variable
- No API submission or buffering (log only for initial implementation)

## Architecture

### New Module: `src/snmp/trap.rs`

A dedicated trap listener that:
1. Binds a UDP socket to the configured trap port
2. Receives incoming SNMP trap packets
3. Parses both SNMPv1 and SNMPv2c trap PDUs using ASN.1/BER decoding
4. Sends parsed traps through a channel for logging

### Scheduler Integration

The trap listener runs as a concurrent task alongside existing polling tasks in the `tokio::select!` loop. It communicates via `tokio::sync::mpsc` channel.

## Trap PDU Formats

### SNMPv1 Trap-PDU

```
Trap-PDU ::= [4] SEQUENCE {
    enterprise    OBJECT IDENTIFIER,
    agent-addr    NetworkAddress,
    generic-trap  INTEGER (0..6),
    specific-trap INTEGER,
    time-stamp    TimeTicks,
    variable-bindings VarBindList
}
```

Generic trap types:
- 0: coldStart
- 1: warmStart
- 2: linkDown
- 3: linkUp
- 4: authenticationFailure
- 5: egpNeighborLoss
- 6: enterpriseSpecific

### SNMPv2c Trap-PDU

```
SNMPv2-Trap-PDU ::= [7] SEQUENCE {
    request-id   INTEGER,
    error-status INTEGER,
    error-index  INTEGER,
    variable-bindings VarBindList
}
```

The trap OID is in the second varbind (`snmpTrapOID.0 = 1.3.6.1.6.3.1.1.4.1.0`).

## Data Structures

```rust
pub enum SnmpVersion {
    V1,
    V2c,
}

pub struct SnmpTrap {
    pub source_addr: SocketAddr,
    pub version: SnmpVersion,
    pub community: String,
    pub trap_oid: String,           // Enterprise OID (v1) or snmpTrapOID (v2c)
    pub generic_trap: Option<u8>,   // v1 only
    pub specific_trap: Option<u32>, // v1 only
    pub uptime: u32,
    pub varbinds: Vec<(String, String)>,
}

pub struct TrapListener {
    port: u16,
}
```

## CLI Configuration

New flag:
```
--trap-port <PORT>    UDP port for SNMP trap listener [default: 162] [env: TRAP_PORT]
```

## Environment Variables

- `LOG_LEVEL` - Controls log verbosity: error, warn, info, debug, trace (default: info)
- `TRAP_PORT` - UDP port for trap listener (default: 162)

## Log Output Format

```
INFO SNMP trap from 192.168.1.1:161 [v1] enterprise=1.3.6.1.4.1.9.9.41 generic=6 specific=1 uptime=12345 varbinds=[1.3.6.1.2.1.2.2.1.1=2, 1.3.6.1.2.1.2.2.1.8=1]

INFO SNMP trap from 192.168.1.1:161 [v2c] oid=1.3.6.1.6.3.1.1.5.4 uptime=12345 varbinds=[ifIndex.2=2, ifOperStatus.2=1]
```

## Docker Compose Configuration

```yaml
services:
  towerops-agent:
    image: towerops/agent:latest
    environment:
      - TOWEROPS_API_URL=http://host.docker.internal:4000
      - TOWEROPS_AGENT_TOKEN=${AGENT_TOKEN}
      - LOG_LEVEL=info
      - TRAP_PORT=162
    ports:
      - "162:162/udp"
    volumes:
      - ./data:/data
```

## Implementation Notes

### BER Parsing

Implement minimal BER decoder for:
- Reading TLV (Tag-Length-Value) structures
- Extracting SNMP version from message wrapper
- Parsing INTEGER, OCTET STRING, OBJECT IDENTIFIER, SEQUENCE types
- Converting values to display strings

### Error Handling

- Malformed packets: log as warning and skip
- UDP socket errors: log and continue listening
- No crash on invalid data

### Privileges

Port 162 requires elevated privileges. In Docker, handled by:
- Container running as root (default), or
- `NET_BIND_SERVICE` capability

## Files to Create/Modify

1. **Create** `src/snmp/trap.rs` - Trap listener and BER parser
2. **Modify** `src/snmp/mod.rs` - Export trap module
3. **Modify** `src/main.rs` - Add CLI flag, configure logging with LOG_LEVEL
4. **Modify** `src/poller/scheduler.rs` - Integrate trap listener task
5. **Modify** `docker-compose.example.yml` - Add trap port and LOG_LEVEL
