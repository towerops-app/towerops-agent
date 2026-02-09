use std::collections::VecDeque;
use std::time::Instant;

use super::events::AgentEvent;

#[derive(Clone)]
pub struct AgentState {
    // Connection
    pub connected: bool,
    pub agent_id: String,

    // System info
    pub hostname: String,
    pub version: String,
    pub started_at: Instant,

    // Active jobs
    pub active_pollers: usize,
    pub active_devices: Vec<String>,

    // Event log (ring buffer, last 100 events)
    pub recent_events: VecDeque<(Instant, String)>,

    // Statistics
    pub stats: Stats,
}

#[derive(Clone, Default)]
pub struct Stats {
    pub jobs_received: u64,
    pub snmp_results_sent: u64,
    pub mikrotik_results_sent: u64,
    pub heartbeats_sent: u64,
    pub errors: u64,
    pub last_heartbeat_at: Option<Instant>,
}

impl AgentState {
    pub fn new(hostname: String, version: String) -> Self {
        Self {
            connected: false,
            agent_id: String::new(),
            hostname,
            version,
            started_at: Instant::now(),
            active_pollers: 0,
            active_devices: Vec::new(),
            recent_events: VecDeque::with_capacity(100),
            stats: Stats::default(),
        }
    }

    pub fn apply_event(&mut self, event: &AgentEvent) {
        let now = Instant::now();
        let event_msg = match event {
            AgentEvent::Connected { agent_id } => {
                self.connected = true;
                self.agent_id = agent_id.clone();
                format!("Connected to server (agent_id: {})", agent_id)
            }
            AgentEvent::Disconnected => {
                self.connected = false;
                "Disconnected from server".to_string()
            }
            AgentEvent::JobReceived {
                job_id,
                device_id,
                job_type,
            } => {
                self.stats.jobs_received += 1;
                format!("Job received: {} ({} - {})", job_id, device_id, job_type)
            }
            AgentEvent::JobCompleted {
                job_id,
                device_id,
                duration_ms,
            } => {
                format!(
                    "Job completed: {} ({}) in {}ms",
                    job_id, device_id, duration_ms
                )
            }
            AgentEvent::JobFailed {
                job_id,
                device_id,
                error,
            } => {
                self.stats.errors += 1;
                format!("Job failed: {} ({}) - {}", job_id, device_id, error)
            }
            AgentEvent::SnmpResultSent {
                device_id,
                oid_count,
            } => {
                self.stats.snmp_results_sent += 1;
                format!("SNMP result sent for {} ({} OIDs)", device_id, oid_count)
            }
            AgentEvent::MikrotikResultSent {
                device_id,
                sentence_count,
            } => {
                self.stats.mikrotik_results_sent += 1;
                format!(
                    "MikroTik result sent for {} ({} sentences)",
                    device_id, sentence_count
                )
            }
            AgentEvent::MonitoringCheckSent { device_id, status } => {
                format!(
                    "Monitoring check sent for {} (status: {})",
                    device_id, status
                )
            }
            AgentEvent::PollerCreated {
                device_ip,
                total_count,
            } => {
                self.active_pollers = *total_count;
                if !self.active_devices.contains(device_ip) {
                    self.active_devices.push(device_ip.clone());
                }
                format!(
                    "Poller created for {} ({} total pollers)",
                    device_ip, total_count
                )
            }
            AgentEvent::PollerRemoved {
                device_ip,
                total_count,
            } => {
                self.active_pollers = *total_count;
                self.active_devices.retain(|d| d != device_ip);
                format!(
                    "Poller removed for {} ({} total pollers)",
                    device_ip, total_count
                )
            }
            AgentEvent::HeartbeatSent => {
                self.stats.heartbeats_sent += 1;
                self.stats.last_heartbeat_at = Some(now);
                "Heartbeat sent".to_string()
            }
            AgentEvent::PhxHeartbeatSent => "Phoenix heartbeat sent".to_string(),
            AgentEvent::Error { message } => {
                self.stats.errors += 1;
                format!("Error: {}", message)
            }
        };

        // Add event to ring buffer (keep last 100)
        if self.recent_events.len() >= 100 {
            self.recent_events.pop_front();
        }
        self.recent_events.push_back((now, event_msg));
    }

    pub fn uptime_seconds(&self) -> u64 {
        self.started_at.elapsed().as_secs()
    }

    pub fn format_uptime(&self) -> String {
        let seconds = self.uptime_seconds();
        let hours = seconds / 3600;
        let minutes = (seconds % 3600) / 60;
        let secs = seconds % 60;
        format!("{}h {}m {}s", hours, minutes, secs)
    }

    pub fn last_heartbeat_ago(&self) -> Option<u64> {
        self.stats.last_heartbeat_at.map(|t| t.elapsed().as_secs())
    }
}
