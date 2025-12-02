//! 수신자 (클라이언트측)
//!
//! - 청크 수신 및 조립
//! - NACK 기반 재전송 요청
//! - 최소 업링크 부담

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use bytes::Bytes;
use tokio::net::UdpSocket;
use tokio::sync::{mpsc, RwLock};
use tracing::{debug, info, warn};

use crate::chunk::{Chunk, ChunkId, Segment, SegmentId};
use crate::message::{InitMessage, NackMessage, SegmentCompleteMessage};
use crate::multipath::PathManager;
use crate::stats::TransferStats;
use crate::{Config, Error, Result};

/// 완료된 세그먼트 채널 수신기 타입
pub type SegmentReceiver = mpsc::Receiver<(SegmentId, Bytes)>;

/// 내부 명령
enum ReceiverCmd {
    Chunk(Chunk),
    SendNacks,
    Stop,
}

/// 세그먼트 상태
struct SegmentState {
    segment: Segment,
    last_nack_time: Instant,
}

/// 수신자 내부 상태 (단일 태스크에서만 접근)
struct ReceiverInner {
    config: Config,
    segments: HashMap<SegmentId, SegmentState>,
    stats: TransferStats,
    server_addr: SocketAddr,
    socket: Arc<UdpSocket>,
    completed_tx: mpsc::Sender<(SegmentId, Bytes)>,
    completed_count: u64,
    path_manager: Arc<PathManager>,
}

impl ReceiverInner {
    fn new(
        config: Config,
        server_addr: SocketAddr,
        socket: Arc<UdpSocket>,
        completed_tx: mpsc::Sender<(SegmentId, Bytes)>,
        path_manager: Arc<PathManager>,
    ) -> Self {
        let nic_count = path_manager.nic_count().max(1);
        Self {
            stats: TransferStats::new(nic_count, config.stats_window_size),
            config,
            segments: HashMap::new(),
            server_addr,
            socket,
            completed_tx,
            completed_count: 0,
            path_manager,
        }
    }

    async fn handle_chunk(&mut self, chunk: Chunk) {
        let segment_id = chunk.header.segment_id;
        let nic_id = chunk.header.nic_id;
        let chunk_size = chunk.data.len();

        // NIC 통계 기록
        self.path_manager.record_chunk_arrival(nic_id, chunk_size);

        // 세그먼트 가져오기 또는 생성
        let state = self.segments.entry(segment_id).or_insert_with(|| {
            self.stats.total_segments += 1;
            SegmentState {
                segment: Segment::new_for_receive(
                    segment_id,
                    chunk.header.segment_size as usize,
                    chunk.header.total_chunks,
                ),
                last_nack_time: Instant::now(),
            }
        });

        // 청크 삽입
        let inserted = state.segment.insert_chunk(&chunk);

        if inserted {
            self.stats.total_chunks += 1;
            self.stats.total_bytes += chunk_size as u64;

            if let Some(nic_stat) = self.stats.nic_stats.get_mut(nic_id as usize) {
                nic_stat.record_arrival(chunk_size);
            }
        } else if chunk.header.is_redundant {
            self.stats.redundant_chunks += 1;
        }

        // 세그먼트 완료 처리
        if state.segment.is_complete() {
            self.handle_segment_complete(segment_id).await;
        }
    }

    async fn handle_segment_complete(&mut self, segment_id: SegmentId) {
        if let Some(state) = self.segments.remove(&segment_id) {
            let elapsed = state.segment.created_at.elapsed();
            let data = state.segment.into_data();

            debug!(
                "세그먼트 {} 완료: {} bytes, {:.2}ms",
                segment_id,
                data.len(),
                elapsed.as_secs_f64() * 1000.0
            );

            // 완료 메시지 전송
            let complete_msg = SegmentCompleteMessage {
                segment_id,
                total_chunks_received: 0,
                duplicates_received: 0,
                elapsed_ms: elapsed.as_millis() as u64,
            };
            let _ = self
                .socket
                .send_to(&complete_msg.to_bytes(), self.server_addr)
                .await;

            // 완료 채널로 전송
            let _ = self.completed_tx.send((segment_id, data)).await;

            self.stats.completed_segments += 1;
            self.completed_count += 1;
        }
    }

    async fn send_nacks(&mut self) {
        let now = Instant::now();
        let nack_timeout = Duration::from_millis(self.config.nack_timeout_ms);

        // NACK 전송할 세그먼트 수집
        let mut nacks_to_send: Vec<(SegmentId, Vec<ChunkId>, f32)> = Vec::new();

        for (&segment_id, state) in &self.segments {
            // 타임아웃 확인
            if now.duration_since(state.last_nack_time) < nack_timeout {
                continue;
            }

            let missing = state.segment.missing_chunk_ids();
            if missing.is_empty() {
                continue;
            }

            // 수신률이 너무 낮으면 아직 전송 중
            if state.segment.receive_ratio() < 0.5
                && state.segment.created_at.elapsed().as_millis() < 100
            {
                continue;
            }

            nacks_to_send.push((segment_id, missing, state.segment.receive_ratio() as f32));
        }

        // NACK 전송
        for (segment_id, missing, receive_ratio) in nacks_to_send {
            let nack = NackMessage::new(segment_id, missing.clone(), receive_ratio, 0);

            if let Err(e) = self.socket.send_to(&nack.to_bytes(), self.server_addr).await {
                warn!("NACK 전송 실패: {}", e);
                continue;
            }

            debug!(
                "NACK 전송: segment={}, missing={} chunks",
                segment_id,
                missing.len()
            );

            // NACK 시간 업데이트
            if let Some(state) = self.segments.get_mut(&segment_id) {
                state.last_nack_time = now;
            }

            // 통계 업데이트
            self.stats.total_nacks += 1;
            self.stats.last_nack_time = Some(now);

            for nic_stat in self.stats.nic_stats.iter_mut() {
                nic_stat.record_loss(missing.len() as u64);
            }

            self.path_manager.record_loss(0, missing.len() as u64);
        }

        // 타임아웃 세그먼트 정리
        let segment_timeout = Duration::from_millis(self.config.segment_timeout_ms);
        self.segments.retain(|segment_id, state| {
            if state.segment.created_at.elapsed() > segment_timeout {
                warn!(
                    "세그먼트 {} 타임아웃: {:.1}% 수신",
                    segment_id,
                    state.segment.receive_ratio() * 100.0
                );
                false
            } else {
                true
            }
        });
    }

    fn get_stats(&self) -> TransferStats {
        self.stats.clone()
    }
}

/// 수신자 핸들 (외부에서 제어용)
pub struct Receiver {
    cmd_tx: mpsc::Sender<ReceiverCmd>,
    stats: Arc<RwLock<TransferStats>>,
    running: Arc<AtomicBool>,
    completed_count: Arc<AtomicU64>,
}

impl Receiver {
    /// 새 수신자 생성 및 시작
    pub async fn start(
        config: Config,
        bind_addr: SocketAddr,
        server_addr: SocketAddr,
        path_manager: Arc<PathManager>,
    ) -> Result<(Self, SegmentReceiver)> {
        // 소켓 생성
        let socket = Arc::new(UdpSocket::bind(bind_addr).await?);

        // 채널 생성
        let (cmd_tx, mut cmd_rx) = mpsc::channel::<ReceiverCmd>(1000);
        let (completed_tx, completed_rx) = mpsc::channel::<(SegmentId, Bytes)>(100);

        // 공유 상태
        let stats = Arc::new(RwLock::new(TransferStats::new(
            path_manager.nic_count().max(1),
            config.stats_window_size,
        )));
        let running = Arc::new(AtomicBool::new(true));
        let completed_count = Arc::new(AtomicU64::new(0));

        // 초기화 메시지 전송
        let init = InitMessage::new(false, [0u8; 32]);
        socket.send_to(&init.to_bytes(), server_addr).await?;

        info!("SLS Receiver started on {}, server: {}", bind_addr, server_addr);

        // 내부 상태
        let mut inner = ReceiverInner::new(
            config.clone(),
            server_addr,
            socket.clone(),
            completed_tx,
            path_manager,
        );

        // 수신 태스크
        let socket_recv = socket.clone();
        let cmd_tx_recv = cmd_tx.clone();
        let running_recv = running.clone();

        tokio::spawn(async move {
            let mut buf = vec![0u8; 65535];

            while running_recv.load(Ordering::SeqCst) {
                match tokio::time::timeout(
                    Duration::from_millis(10),
                    socket_recv.recv_from(&mut buf),
                )
                .await
                {
                    Ok(Ok((len, _addr))) => {
                        if let Some(chunk) = Chunk::from_bytes(&buf[..len]) {
                            let _ = cmd_tx_recv.send(ReceiverCmd::Chunk(chunk)).await;
                        }
                    }
                    Ok(Err(e)) => {
                        warn!("수신 에러: {}", e);
                    }
                    Err(_) => {
                        // 타임아웃, 계속
                    }
                }
            }
        });

        // NACK 타이머 태스크
        let cmd_tx_nack = cmd_tx.clone();
        let running_nack = running.clone();
        let nack_timeout = config.nack_timeout_ms;

        tokio::spawn(async move {
            while running_nack.load(Ordering::SeqCst) {
                tokio::time::sleep(Duration::from_millis(nack_timeout)).await;
                let _ = cmd_tx_nack.send(ReceiverCmd::SendNacks).await;
            }
        });

        // 메인 처리 태스크
        let stats_main = stats.clone();
        let running_main = running.clone();
        let completed_count_main = completed_count.clone();

        tokio::spawn(async move {
            while let Some(cmd) = cmd_rx.recv().await {
                match cmd {
                    ReceiverCmd::Chunk(chunk) => {
                        inner.handle_chunk(chunk).await;
                    }
                    ReceiverCmd::SendNacks => {
                        inner.send_nacks().await;
                    }
                    ReceiverCmd::Stop => {
                        break;
                    }
                }

                // 통계 업데이트
                *stats_main.write().await = inner.get_stats();
                completed_count_main.store(inner.completed_count, Ordering::Relaxed);
            }

            running_main.store(false, Ordering::SeqCst);
        });

        let receiver = Self {
            cmd_tx,
            stats,
            running,
            completed_count,
        };

        Ok((receiver, completed_rx))
    }

    /// 정지
    pub async fn stop(&self) {
        self.running.store(false, Ordering::SeqCst);
        let _ = self.cmd_tx.send(ReceiverCmd::Stop).await;
    }

    /// 통계 반환
    pub async fn get_stats(&self) -> TransferStats {
        self.stats.read().await.clone()
    }

    /// 완료된 세그먼트 수
    pub fn completed_segments(&self) -> u64 {
        self.completed_count.load(Ordering::Relaxed)
    }

    /// 실행 중 여부
    pub fn is_running(&self) -> bool {
        self.running.load(Ordering::SeqCst)
    }
}

/// 간단한 파일 수신용 수신자
pub struct FileReceiver {
    receiver: Receiver,
    segment_rx: Option<SegmentReceiver>,
}

impl FileReceiver {
    pub async fn new(
        config: Config,
        bind_addr: SocketAddr,
        server_addr: SocketAddr,
    ) -> Result<Self> {
        let path_manager = Arc::new(PathManager::new(config.clone()));
        let (receiver, segment_rx) = Receiver::start(config, bind_addr, server_addr, path_manager).await?;

        Ok(Self {
            receiver,
            segment_rx: Some(segment_rx),
        })
    }

    /// 파일 데이터 수신 (모든 세그먼트 조합)
    pub async fn receive_file(&mut self, expected_segments: usize) -> Result<Vec<u8>> {
        let mut segment_rx = self
            .segment_rx
            .take()
            .ok_or_else(|| Error::Unknown("이미 수신 중".into()))?;

        let mut received_segments: HashMap<SegmentId, Bytes> = HashMap::new();

        while received_segments.len() < expected_segments {
            match tokio::time::timeout(Duration::from_secs(30), segment_rx.recv()).await {
                Ok(Some((segment_id, data))) => {
                    received_segments.insert(segment_id, data);
                    info!(
                        "세그먼트 수신: {}/{} 완료",
                        received_segments.len(),
                        expected_segments
                    );
                }
                Ok(None) => {
                    return Err(Error::ConnectionClosed);
                }
                Err(_) => {
                    return Err(Error::SegmentTimeout {
                        segment_id: received_segments.len() as u64,
                    });
                }
            }
        }

        // 세그먼트 순서대로 조합
        let mut result = Vec::new();
        for i in 1..=(expected_segments as u64) {
            if let Some(data) = received_segments.remove(&i) {
                result.extend_from_slice(&data);
            }
        }

        self.segment_rx = Some(segment_rx);
        Ok(result)
    }

    /// 통계 반환
    pub async fn stats(&self) -> TransferStats {
        self.receiver.get_stats().await
    }
}
