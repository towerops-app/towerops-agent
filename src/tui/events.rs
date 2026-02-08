use tokio::sync::broadcast;

#[derive(Debug, Clone)]
pub enum AgentEvent {
    Connected {
        agent_id: String,
    },
    Disconnected,
    JobReceived {
        job_id: String,
        device_id: String,
        job_type: String,
    },
    JobCompleted {
        job_id: String,
        device_id: String,
        duration_ms: u64,
    },
    JobFailed {
        job_id: String,
        device_id: String,
        error: String,
    },
    SnmpResultSent {
        device_id: String,
        oid_count: usize,
    },
    MikrotikResultSent {
        device_id: String,
        sentence_count: usize,
    },
    MonitoringCheckSent {
        device_id: String,
        status: String,
    },
    PollerCreated {
        device_ip: String,
        total_count: usize,
    },
    PollerRemoved {
        device_ip: String,
        total_count: usize,
    },
    HeartbeatSent,
    PhxHeartbeatSent,
    Error {
        message: String,
    },
}

#[derive(Clone)]
pub struct EventBus {
    tx: broadcast::Sender<AgentEvent>,
}

impl EventBus {
    pub fn new(capacity: usize) -> Self {
        let (tx, _) = broadcast::channel(capacity);
        Self { tx }
    }

    pub fn subscribe(&self) -> broadcast::Receiver<AgentEvent> {
        self.tx.subscribe()
    }

    pub fn send(
        &self,
        event: AgentEvent,
    ) -> Result<usize, broadcast::error::SendError<AgentEvent>> {
        self.tx.send(event)
    }
}
