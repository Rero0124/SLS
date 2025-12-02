#[derive(Debug)]
pub struct BbrLite {
    pub pacing_rate: f64,   // bytes/sec
    pub min_rtt: f64,       // seconds
    pub last_rtt: f64,      // seconds
    pub delivered_bytes: u64,
    pub delivered_prev: u64,
    pub last_ts: std::time::Instant,

    // parameters
    pub gain: f64,
    pub probe_interval: f64,
}

impl BbrLite {
    pub fn new(initial_rtt: f64, initial_rate: f64) -> Self {
        Self {
            pacing_rate: initial_rate,     // 초기 대역폭 추정값
            min_rtt: initial_rtt,
            last_rtt: initial_rtt,
            delivered_bytes: 0,
            delivered_prev: 0,
            last_ts: std::time::Instant::now(),

            gain: 1.0,
            probe_interval: 0.20, // 200ms
        }
    }

    // 호출 위치: 송신 성공 시
    pub fn on_packet_sent(&mut self, bytes: usize) {
        self.delivered_bytes += bytes as u64;
    }

    // 호출 위치: RTT 샘플 도착 시
    pub fn on_rtt_update(&mut self, rtt: f64) {
        self.last_rtt = rtt;
        if rtt < self.min_rtt {
            self.min_rtt = rtt;
        }
    }

    // 호출 위치: 주기적 (예: 50~100ms )
    pub fn update_rate(&mut self) {
        let now = std::time::Instant::now();
        let dt = now.duration_since(self.last_ts).as_secs_f64();

        if dt < self.probe_interval {
            return; // 아직 갱신할 때 아님
        }

        let delivered = self.delivered_bytes - self.delivered_prev;
        let delivery_rate = (delivered as f64 / dt).max(1.0);

        self.delivered_prev = self.delivered_bytes;
        self.last_ts = now;

        let btlbw = delivered as f64 / self.last_rtt.max(0.000001);
        let queue_ratio = self.last_rtt / self.min_rtt.max(0.000001);

        let gain = (- (queue_ratio - 1.0)).exp();
        self.pacing_rate *= btlbw * gain;

        // delivery_rate를 기반으로 보정
        self.pacing_rate = self.pacing_rate.max(delivery_rate * 0.8);

        // 상한/하한
        self.pacing_rate = self.pacing_rate.clamp(10_000_000.0, 5_000_000_000.0);
    }

    // pacing delay 계산
    pub fn pacing_delay(&self, packet_size: usize) -> std::time::Duration {
        let sec = (packet_size as f64 / self.pacing_rate).max(0.000_001);
        std::time::Duration::from_secs_f64(sec)
    }
}