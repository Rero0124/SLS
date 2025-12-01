//! 전송 통계

use std::collections::VecDeque;
use std::time::{Duration, Instant};

/// 청크 도착 기록
#[derive(Debug, Clone, Copy)]
struct ChunkArrival {
    timestamp: Instant,
    size: usize,
    #[allow(dead_code)]
    nic_id: u8,
}

/// NIC별 통계
#[derive(Debug, Clone)]
pub struct NicStats {
    /// NIC ID
    pub nic_id: u8,

    /// 최근 청크 도착 기록
    arrivals: VecDeque<ChunkArrival>,

    /// 윈도우 크기
    window_size: usize,

    /// 총 수신 청크 수
    pub total_chunks: u64,

    /// 총 수신 바이트
    pub total_bytes: u64,

    /// 손실된 청크 수 (NACK 기반)
    pub lost_chunks: u64,

    /// 중복 수신 청크 수
    pub duplicate_chunks: u64,

    /// RTT 샘플 (마이크로초)
    rtt_samples: VecDeque<u64>,

    /// 마지막 업데이트 시간
    last_update: Instant,
}

impl NicStats {
    pub fn new(nic_id: u8, window_size: usize) -> Self {
        Self {
            nic_id,
            arrivals: VecDeque::with_capacity(window_size),
            window_size,
            total_chunks: 0,
            total_bytes: 0,
            lost_chunks: 0,
            duplicate_chunks: 0,
            rtt_samples: VecDeque::with_capacity(10),
            last_update: Instant::now(),
        }
    }

    /// 청크 도착 기록
    pub fn record_arrival(&mut self, size: usize) {
        let now = Instant::now();

        if self.arrivals.len() >= self.window_size {
            self.arrivals.pop_front();
        }

        self.arrivals.push_back(ChunkArrival {
            timestamp: now,
            size,
            nic_id: self.nic_id,
        });

        self.total_chunks += 1;
        self.total_bytes += size as u64;
        self.last_update = now;
    }

    /// 손실 기록
    pub fn record_loss(&mut self, count: u64) {
        self.lost_chunks += count;
    }

    /// 중복 기록
    pub fn record_duplicate(&mut self) {
        self.duplicate_chunks += 1;
    }

    /// RTT 샘플 기록
    pub fn record_rtt(&mut self, rtt_us: u64) {
        if self.rtt_samples.len() >= 10 {
            self.rtt_samples.pop_front();
        }
        self.rtt_samples.push_back(rtt_us);
    }

    /// 청크 도착률 계산 (chunks/sec)
    pub fn chunk_arrival_rate(&self) -> f64 {
        if self.arrivals.len() < 2 {
            return 0.0;
        }

        let first = self.arrivals.front().unwrap().timestamp;
        let last = self.arrivals.back().unwrap().timestamp;
        let duration = last.duration_since(first);

        if duration.is_zero() {
            return 0.0;
        }

        (self.arrivals.len() - 1) as f64 / duration.as_secs_f64()
    }

    /// 바이트 처리율 계산 (bytes/sec)
    pub fn throughput(&self) -> f64 {
        if self.arrivals.len() < 2 {
            return 0.0;
        }

        let first = self.arrivals.front().unwrap().timestamp;
        let last = self.arrivals.back().unwrap().timestamp;
        let duration = last.duration_since(first);

        if duration.is_zero() {
            return 0.0;
        }

        let total_size: usize = self.arrivals.iter().map(|a| a.size).sum();
        total_size as f64 / duration.as_secs_f64()
    }

    /// 손실률 계산
    pub fn loss_rate(&self) -> f64 {
        let total = self.total_chunks + self.lost_chunks;
        if total == 0 {
            return 0.0;
        }
        self.lost_chunks as f64 / total as f64
    }

    /// 평균 RTT 계산 (마이크로초)
    pub fn average_rtt_us(&self) -> Option<u64> {
        if self.rtt_samples.is_empty() {
            return None;
        }
        Some(self.rtt_samples.iter().sum::<u64>() / self.rtt_samples.len() as u64)
    }

    /// 통계 리셋
    pub fn reset(&mut self) {
        self.arrivals.clear();
        self.total_chunks = 0;
        self.total_bytes = 0;
        self.lost_chunks = 0;
        self.duplicate_chunks = 0;
        self.rtt_samples.clear();
        self.last_update = Instant::now();
    }
}

/// 전체 전송 통계
#[derive(Debug, Clone)]
pub struct TransferStats {
    /// 시작 시간
    pub start_time: Instant,

    /// 총 세그먼트 수
    pub total_segments: u64,

    /// 완료된 세그먼트 수
    pub completed_segments: u64,

    /// 총 전송 바이트
    pub total_bytes: u64,

    /// 총 청크 수
    pub total_chunks: u64,

    /// 재전송 청크 수
    pub retransmitted_chunks: u64,

    /// 중복 전송 청크 수
    pub redundant_chunks: u64,

    /// NIC별 통계
    pub nic_stats: Vec<NicStats>,

    /// 마지막 NACK 시간
    pub last_nack_time: Option<Instant>,

    /// 총 NACK 수
    pub total_nacks: u64,
}

impl TransferStats {
    pub fn new(nic_count: usize, window_size: usize) -> Self {
        Self {
            start_time: Instant::now(),
            total_segments: 0,
            completed_segments: 0,
            total_bytes: 0,
            total_chunks: 0,
            retransmitted_chunks: 0,
            redundant_chunks: 0,
            nic_stats: (0..nic_count)
                .map(|i| NicStats::new(i as u8, window_size))
                .collect(),
            last_nack_time: None,
            total_nacks: 0,
        }
    }

    /// 경과 시간
    pub fn elapsed(&self) -> Duration {
        self.start_time.elapsed()
    }

    /// 전체 처리율 (bytes/sec)
    pub fn overall_throughput(&self) -> f64 {
        let elapsed = self.elapsed().as_secs_f64();
        if elapsed == 0.0 {
            return 0.0;
        }
        self.total_bytes as f64 / elapsed
    }

    /// 실효 처리율 (중복 제외)
    pub fn effective_throughput(&self) -> f64 {
        let elapsed = self.elapsed().as_secs_f64();
        if elapsed == 0.0 {
            return 0.0;
        }

        // 중복/재전송 제외한 유효 바이트
        let effective_chunks = self.total_chunks
            .saturating_sub(self.redundant_chunks)
            .saturating_sub(self.retransmitted_chunks);

        // 대략적 추정 (청크당 평균 크기)
        let avg_chunk_size = if self.total_chunks > 0 {
            self.total_bytes as f64 / self.total_chunks as f64
        } else {
            1200.0
        };

        (effective_chunks as f64 * avg_chunk_size) / elapsed
    }

    /// 전체 손실률
    pub fn overall_loss_rate(&self) -> f64 {
        let total_lost: u64 = self.nic_stats.iter().map(|s| s.lost_chunks).sum();
        let total = self.total_chunks + total_lost;
        if total == 0 {
            return 0.0;
        }
        total_lost as f64 / total as f64
    }

    /// 실효 대역폭 공식 계산
    /// real_throughput = raw_bandwidth × (1 - loss_rate) × (1 - redundancy_ratio)
    pub fn calculate_real_throughput(&self, raw_bandwidth: f64) -> f64 {
        let loss_rate = self.overall_loss_rate();
        let redundancy_ratio = if self.total_chunks > 0 {
            self.redundant_chunks as f64 / self.total_chunks as f64
        } else {
            0.0
        };

        raw_bandwidth * (1.0 - loss_rate) * (1.0 - redundancy_ratio)
    }

    /// NIC별 비율 계산
    pub fn nic_ratios(&self) -> Vec<f64> {
        let total_throughput: f64 = self.nic_stats.iter().map(|s| s.throughput()).sum();
        if total_throughput == 0.0 {
            // 균등 분배
            let count = self.nic_stats.len();
            return vec![1.0 / count as f64; count];
        }

        self.nic_stats
            .iter()
            .map(|s| s.throughput() / total_throughput)
            .collect()
    }

    /// 통계 요약 문자열
    pub fn summary(&self) -> String {
        format!(
            "Elapsed: {:.2}s | Segments: {}/{} | Bytes: {} | Throughput: {:.2} MB/s | Loss: {:.2}% | NACKs: {}",
            self.elapsed().as_secs_f64(),
            self.completed_segments,
            self.total_segments,
            self.total_bytes,
            self.overall_throughput() / 1_000_000.0,
            self.overall_loss_rate() * 100.0,
            self.total_nacks,
        )
    }
}

impl Default for TransferStats {
    fn default() -> Self {
        Self::new(1, 100)
    }
}
