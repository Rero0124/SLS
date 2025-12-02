//! 송신자 (서버측)
//!
//! - 공격적 청크 전송
//! - Forward Redundancy
//! - NIC 비율 기반 멀티패스

use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use bytes::Bytes;
use dashmap::DashMap;
use parking_lot::RwLock;
use tokio::net::UdpSocket;
use tracing::{debug, info, warn};

use crate::chunk::{Chunk, ChunkId, SegmentBuilder, SegmentId};
use crate::message::{InitAckMessage, MessageHeader, MessageType, NackMessage};
use crate::multipath::PathManager;
use crate::stats::TransferStats;
use crate::{Config, Error, Result, MAGIC_NUMBER};

/// 세그먼트 전송 상태
#[derive(Debug)]
#[allow(dead_code)]
struct SegmentState {
    /// 원본 청크들
    chunks: Vec<Chunk>,

    /// 중복 청크들
    redundant_chunks: Vec<Chunk>,

    /// 전송된 청크 ID
    sent_chunk_ids: Vec<bool>,

    /// 생성 시간
    created_at: Instant,

    /// 완료 여부
    completed: bool,

    /// 재전송 요청된 청크 ID
    retransmit_queue: Vec<ChunkId>,
}

/// 송신자
pub struct Sender {
    /// 설정
    config: Config,

    /// 경로 관리자
    path_manager: Arc<PathManager>,

    /// 세그먼트 빌더
    segment_builder: SegmentBuilder,

    /// 활성 세그먼트 상태
    segments: DashMap<SegmentId, SegmentState>,

    /// 다음 세그먼트 ID
    next_segment_id: AtomicU64,

    /// 전송 통계
    stats: RwLock<TransferStats>,

    /// 현재 중복률
    current_redundancy: RwLock<f64>,

    /// 실행 중 플래그
    running: AtomicBool,

    /// 클라이언트 주소
    client_addr: RwLock<Option<SocketAddr>>,
}

impl Sender {
    /// 새 송신자 생성
    pub fn new(config: Config, path_manager: Arc<PathManager>) -> Self {
        let stats = TransferStats::new(path_manager.nic_count().max(1), config.stats_window_size);

        Self {
            segment_builder: SegmentBuilder::new(config.chunk_size),
            current_redundancy: RwLock::new(config.base_redundancy_ratio),
            config,
            path_manager,
            segments: DashMap::new(),
            next_segment_id: AtomicU64::new(1),
            stats: RwLock::new(stats),
            running: AtomicBool::new(false),
            client_addr: RwLock::new(None),
        }
    }

    /// 서버 시작
    pub async fn start(&self, bind_addr: SocketAddr) -> Result<()> {
        self.running.store(true, Ordering::SeqCst);

        // 메인 소켓 바인딩
        let socket = Arc::new(UdpSocket::bind(bind_addr).await?);
        socket.set_broadcast(true)?;

        info!("SLS Sender started on {}", bind_addr);

        // 수신 루프 (NACK 처리)
        let socket_clone = socket.clone();
        let self_ref = self;
        
        let mut buf = vec![0u8; 65535];

        while self.running.load(Ordering::SeqCst) {
            tokio::select! {
                result = socket_clone.recv_from(&mut buf) => {
                    match result {
                        Ok((len, addr)) => {
                            if let Err(e) = self_ref.handle_message(&buf[..len], addr, &socket_clone).await {
                                warn!("메시지 처리 에러: {}", e);
                            }
                        }
                        Err(e) => {
                            warn!("수신 에러: {}", e);
                        }
                    }
                }
                _ = tokio::time::sleep(Duration::from_millis(10)) => {
                    // 주기적 작업
                    self_ref.process_retransmits(&socket_clone).await;
                    self_ref.path_manager.adjust_ratios();
                    self_ref.update_redundancy();
                }
            }
        }

        Ok(())
    }

    /// 데이터 전송 (비동기)
    pub async fn send_data(&self, data: Bytes, socket: &UdpSocket) -> Result<SegmentId> {
        let segment_id = self.next_segment_id.fetch_add(1, Ordering::SeqCst);

        // 청크 분할
        let nic_id = self.path_manager.select_nic_for_chunk().unwrap_or(0);
        let chunks = self.segment_builder.split_into_chunks(segment_id, &data, nic_id);

        // 중복 청크 생성
        let redundancy = *self.current_redundancy.read();
        let redundant_chunks = self
            .segment_builder
            .create_redundant_chunks(&chunks, redundancy);

        let total_chunks = chunks.len();

        // 상태 저장
        let state = SegmentState {
            chunks: chunks.clone(),
            redundant_chunks: redundant_chunks.clone(),
            sent_chunk_ids: vec![false; total_chunks],
            created_at: Instant::now(),
            completed: false,
            retransmit_queue: Vec::new(),
        };
        self.segments.insert(segment_id, state);

        // 통계 업데이트
        {
            let mut stats = self.stats.write();
            stats.total_segments += 1;
            stats.total_bytes += data.len() as u64;
        }

        // 클라이언트 주소 확인
        let client_addr = match *self.client_addr.read() {
            Some(addr) => addr,
            None => return Err(Error::ConnectionClosed),
        };

        // 청크 전송
        self.transmit_chunks(&chunks, &redundant_chunks, socket, client_addr)
            .await?;

        debug!(
            "세그먼트 {} 전송 완료: {} 청크 + {} 중복",
            segment_id,
            total_chunks,
            redundant_chunks.len()
        );

        Ok(segment_id)
    }

    /// 청크들 전송
    async fn transmit_chunks(
        &self,
        chunks: &[Chunk],
        redundant_chunks: &[Chunk],
        socket: &UdpSocket,
        addr: SocketAddr,
    ) -> Result<()> {
        // 원본 청크 전송
        for chunk in chunks {
            let data = chunk.to_bytes();
            socket.send_to(&data, addr).await?;

            self.path_manager
                .record_chunk_arrival(chunk.header.nic_id, data.len());

            {
                let mut stats = self.stats.write();
                stats.total_chunks += 1;
            }

            // 전송 간격
            if self.config.chunk_interval_us > 0 {
                tokio::time::sleep(Duration::from_micros(self.config.chunk_interval_us)).await;
            }
        }

        // 중복 청크 전송
        for chunk in redundant_chunks {
            let data = chunk.to_bytes();
            socket.send_to(&data, addr).await?;

            {
                let mut stats = self.stats.write();
                stats.redundant_chunks += 1;
                stats.total_chunks += 1;
            }

            if self.config.chunk_interval_us > 0 {
                tokio::time::sleep(Duration::from_micros(self.config.chunk_interval_us)).await;
            }
        }

        Ok(())
    }

    /// 메시지 처리
    async fn handle_message(
        &self,
        data: &[u8],
        addr: SocketAddr,
        socket: &UdpSocket,
    ) -> Result<()> {
        if data.len() < 4 {
            return Ok(());
        }

        // 매직 넘버 확인
        let magic = u32::from_le_bytes([data[0], data[1], data[2], data[3]]);
        if magic != MAGIC_NUMBER {
            // 청크 패킷이 아닌 메시지
            return self.handle_control_message(data, addr, socket).await;
        }

        Ok(())
    }

    /// 컨트롤 메시지 처리
    async fn handle_control_message(
        &self,
        data: &[u8],
        addr: SocketAddr,
        socket: &UdpSocket,
    ) -> Result<()> {
        // 헤더 파싱
        let header: MessageHeader = match bincode::deserialize(data) {
            Ok(h) => h,
            Err(_) => return Ok(()),
        };

        match header.msg_type {
            MessageType::Init => {
                // 연결 초기화
                *self.client_addr.write() = Some(addr);

                let ack = InitAckMessage::new(
                    0, // total_file_size - will be set when data is known
                    self.config.chunk_size as u16,
                    self.config.segment_size as u32,
                    *self.current_redundancy.read() as f32,
                );

                socket.send_to(&ack.to_bytes(), addr).await?;
                info!("클라이언트 연결: {}", addr);
            }

            MessageType::Nack => {
                // NACK 처리
                if let Some(nack) = NackMessage::from_bytes(data) {
                    self.handle_nack(nack, socket, addr).await?;
                }
            }

            MessageType::SegmentComplete => {
                // 세그먼트 완료
                // payload에서 segment_id 추출 (간단 구현)
                if data.len() > 16 {
                    if let Ok(segment_id) = bincode::deserialize::<u64>(&data[16..24]) {
                        self.segments.remove(&segment_id);
                        let mut stats = self.stats.write();
                        stats.completed_segments += 1;
                        debug!("세그먼트 {} 완료 확인", segment_id);
                    }
                }
            }

            MessageType::Heartbeat => {
                // Heartbeat 응답
                let response = crate::message::HeartbeatMessage::new(0);
                socket.send_to(&response.to_bytes(), addr).await?;
            }

            MessageType::Close => {
                *self.client_addr.write() = None;
                info!("클라이언트 연결 종료: {}", addr);
            }

            _ => {}
        }

        Ok(())
    }

    /// NACK 처리
    async fn handle_nack(
        &self,
        nack: NackMessage,
        socket: &UdpSocket,
        addr: SocketAddr,
    ) -> Result<()> {
        debug!(
            "NACK 수신: segment={}, missing={} chunks",
            nack.segment_id,
            nack.missing_chunk_ids.len()
        );

        // 통계 업데이트
        {
            let mut stats = self.stats.write();
            stats.total_nacks += 1;
            stats.last_nack_time = Some(Instant::now());
        }

        // 손실 기록
        self.path_manager
            .record_loss(nack.nic_id, nack.missing_chunk_ids.len() as u64);

        // 재전송 큐에 추가
        if let Some(mut state) = self.segments.get_mut(&nack.segment_id) {
            for chunk_id in &nack.missing_chunk_ids {
                if !state.retransmit_queue.contains(chunk_id) {
                    state.retransmit_queue.push(*chunk_id);
                }
            }
        }

        // 즉시 재전송
        self.retransmit_chunks(nack.segment_id, &nack.missing_chunk_ids, socket, addr)
            .await?;

        Ok(())
    }

    /// 청크 재전송
    async fn retransmit_chunks(
        &self,
        segment_id: SegmentId,
        chunk_ids: &[ChunkId],
        socket: &UdpSocket,
        addr: SocketAddr,
    ) -> Result<()> {
        if let Some(state) = self.segments.get(&segment_id) {
            for &chunk_id in chunk_ids {
                if let Some(chunk) = state.chunks.get(chunk_id as usize) {
                    let data = chunk.to_bytes();
                    socket.send_to(&data, addr).await?;

                    {
                        let mut stats = self.stats.write();
                        stats.retransmitted_chunks += 1;
                        stats.total_chunks += 1;
                    }
                }
            }
        }

        Ok(())
    }

    /// 주기적 재전송 처리
    async fn process_retransmits(&self, socket: &UdpSocket) {
        let client_addr = match *self.client_addr.read() {
            Some(addr) => addr,
            None => return,
        };

        for mut entry in self.segments.iter_mut() {
            let _segment_id = *entry.key();
            let state = entry.value_mut();

            if !state.retransmit_queue.is_empty() {
                let chunks_to_retransmit: Vec<ChunkId> = state.retransmit_queue.drain(..).collect();

                for chunk_id in chunks_to_retransmit {
                    if let Some(chunk) = state.chunks.get(chunk_id as usize) {
                        let data = chunk.to_bytes();
                        if let Err(e) = socket.send_to(&data, client_addr).await {
                            warn!("재전송 실패: {}", e);
                        }
                    }
                }
            }

            // 타임아웃 확인
            if state.created_at.elapsed() > Duration::from_millis(self.config.segment_timeout_ms) {
                state.completed = true;
            }
        }

        // 완료된 세그먼트 정리
        self.segments.retain(|_, state| !state.completed);
    }

    /// 중복률 업데이트
    fn update_redundancy(&self) {
        let new_redundancy = self.path_manager.calculate_redundancy();
        *self.current_redundancy.write() = new_redundancy;
    }

    /// 정지
    pub fn stop(&self) {
        self.running.store(false, Ordering::SeqCst);
    }

    /// 통계 반환
    pub fn get_stats(&self) -> TransferStats {
        self.stats.read().clone()
    }

    /// 현재 중복률
    pub fn current_redundancy_ratio(&self) -> f64 {
        *self.current_redundancy.read()
    }
}

/// 간단한 파일 전송용 송신자
pub struct FileSender {
    sender: Arc<Sender>,
    socket: Arc<UdpSocket>,
}

impl FileSender {
    pub async fn new(config: Config, bind_addr: SocketAddr) -> Result<Self> {
        let path_manager = Arc::new(PathManager::new(config.clone()));
        let sender = Arc::new(Sender::new(config, path_manager));
        let socket = Arc::new(UdpSocket::bind(bind_addr).await?);

        Ok(Self { sender, socket })
    }

    /// 파일 데이터 전송
    pub async fn send_file(&self, data: &[u8], client_addr: SocketAddr) -> Result<()> {
        // 클라이언트 주소 설정
        *self.sender.client_addr.write() = Some(client_addr);

        let segment_size = self.sender.config.segment_size;
        let mut offset = 0;

        while offset < data.len() {
            let end = (offset + segment_size).min(data.len());
            let segment_data = Bytes::copy_from_slice(&data[offset..end]);

            self.sender
                .send_data(segment_data, &self.socket)
                .await?;

            offset = end;
        }

        Ok(())
    }

    /// 통계 반환
    pub fn stats(&self) -> TransferStats {
        self.sender.get_stats()
    }
}
