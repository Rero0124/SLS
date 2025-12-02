//! 대용량 파일 전송 테스트 (병렬 처리 + 암호화 지원)
//!
//! 사용법:
//!   cargo run --release --example large_file_test -- [OPTIONS]
//!
//! 옵션:
//!   --size <MB>       [서버 전용] 테스트 데이터 크기 (MB, 기본: 10)
//!   --server          서버 모드로 실행
//!   --client          클라이언트 모드로 실행 (서버와는 별개로 동작)
//!   --bind, -b <ADDR> 서버/클라이언트 주소 (기본: 127.0.0.1:9000)
//!   --encrypt, -e     암호화 활성화 (X25519 + ChaCha20-Poly1305)
//!   --workers <N>     [서버 전용] 병렬 워커 수 (기본: CPU 코어 수)

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};

use tokio::net::UdpSocket;
use tokio::sync::{mpsc, Mutex, RwLock};
use tracing::{info, warn, Level};
use tracing_subscriber::FmtSubscriber;

use sls::chunk::SegmentBuilder;
use sls::crypto::{CryptoSession, EphemeralKeyPair, KeyExchangeMessage};
use sls::message::{FlowControlMessage, InitAckMessage, MessageHeader, MessageType, NackMessage};
use sls::Config;

/// 테스트용 텍스트 데이터 생성
fn generate_test_text(size_mb: usize) -> Vec<u8> {
    let target_size = size_mb * 1024 * 1024;
    let mut data = Vec::with_capacity(target_size);

    // 다양한 텍스트 패턴 생성
    let patterns = [
        "The quick brown fox jumps over the lazy dog. ",
        "Lorem ipsum dolor sit amet, consectetur adipiscing elit. ",
        "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789 ",
        "가나다라마바사아자차카타파하 ",
        "Hello, World! This is SLS Protocol test data. ",
        "🚀 UDP-based NACK block assembly protocol testing... ",
    ];

    let mut line_num = 0u64;
    while data.len() < target_size {
        // 줄 번호 추가
        let line = format!(
            "[{:08}] {}\n",
            line_num,
            patterns[line_num as usize % patterns.len()]
        );
        data.extend_from_slice(line.as_bytes());
        line_num += 1;
    }

    data.truncate(target_size);
    data
}

/// 데이터 검증 (첫 부분과 끝 부분 확인)
fn verify_data(original: &[u8], received: &[u8]) -> bool {
    if original.len() != received.len() {
        warn!(
            "크기 불일치: expected {} bytes, got {} bytes",
            original.len(),
            received.len()
        );
        return false;
    }

    // 전체 비교
    let mismatches: Vec<usize> = original
        .iter()
        .zip(received.iter())
        .enumerate()
        .filter(|(_, (a, b))| a != b)
        .map(|(i, _)| i)
        .take(10)
        .collect();

    if !mismatches.is_empty() {
        warn!("데이터 불일치 위치: {:?}", mismatches);
        return false;
    }

    true
}

/// 서버 (송신자) 실행 - 병렬 처리 + 암호화 지원
async fn run_server(
    addr: SocketAddr, 
    data: Vec<u8>, 
    config: Config,
    encrypt: bool,
    _num_workers: usize,
) -> Result<(), Box<dyn std::error::Error>> {
    let socket = Arc::new(UdpSocket::bind(addr).await?);
    info!("📡 서버 시작: {}", addr);
    info!("📦 전송 데이터: {} bytes ({:.2} MB)", data.len(), data.len() as f64 / 1024.0 / 1024.0);
    info!("⚙️  청크 크기: {} bytes", config.chunk_size);
    info!("⚙️  세그먼트 크기: {} bytes", config.segment_size);
    info!("⚙️  중복률: {:.1}%", config.base_redundancy_ratio * 100.0);
    info!("⚙️  암호화: {}", if encrypt { "✅ 활성화" } else { "❌ 비활성화" });

    // ═══════════════════════════════════════════════════════════════
    // 송신 큐: 우선순위 큐 (Init, InitAck, KeyExchange) + 데이터 큐 (청크)
    // ═══════════════════════════════════════════════════════════════
    let (priority_tx, mut priority_rx) = mpsc::channel::<(Vec<u8>, SocketAddr)>(1000);
    let (data_tx, mut data_rx) = mpsc::channel::<(Vec<u8>, SocketAddr)>(200_000);

    // ─────────────────────────────────────────────────────────────────
    // 단일 송신 태스크: 우선순위 큐 먼저, 그 다음 데이터 큐
    // ─────────────────────────────────────────────────────────────────
    let send_socket = socket.clone();
    let measured_throughput = Arc::new(std::sync::atomic::AtomicU64::new(0));
    let _measured_clone = measured_throughput.clone();
    
    let _send_task = tokio::spawn(async move {
        let mut bytes_sent_window = 0u64;
        let mut window_start = Instant::now();
        
        loop {
            match priority_rx.try_recv() {
                Ok((bytes, addr)) => {
                    let _ = send_socket.send_to(&bytes, addr).await;
                    continue;
                }
                Err(mpsc::error::TryRecvError::Empty) => {}
                Err(mpsc::error::TryRecvError::Disconnected) => break,
            }

            tokio::select! {
                biased;
                Some((bytes, addr)) = priority_rx.recv() => {
                    let _ = send_socket.send_to(&bytes, addr).await;
                }
                Some((bytes, addr)) = data_rx.recv() => {
                    let packet_len = bytes.len() as u64;
                    let _ = send_socket.send_to(&bytes, addr).await;
                    bytes_sent_window += packet_len;
                    
                    if window_start.elapsed() >= Duration::from_secs(1) {
                        _measured_clone.store(bytes_sent_window, std::sync::atomic::Ordering::Relaxed);
                        bytes_sent_window = 0;
                        window_start = Instant::now();
                    }
                }
                else => break,
            }
        }
    });

    // ═══════════════════════════════════════════════════════════════
    // 수신 큐 + 수신 태스크 (모든 수신은 이 큐를 통해)
    // ═══════════════════════════════════════════════════════════════
    let (recv_tx, recv_rx) = mpsc::channel::<(Vec<u8>, SocketAddr)>(100_000);
    let recv_rx = Arc::new(tokio::sync::Mutex::new(recv_rx));
    
    let recv_socket = socket.clone();
    let _recv_task = tokio::spawn(async move {
        let mut buf = vec![0u8; 2048];
        loop {
            match recv_socket.recv_from(&mut buf).await {
                Ok((len, addr)) => {
                    let _ = recv_tx.try_send((buf[..len].to_vec(), addr));
                }
                Err(_) => break,
            }
        }
    });

    info!("⏳ 클라이언트 연결 대기 중...");

    // Init 메시지 대기 (수신 큐에서)
    let (client_addr, crypto_session) = loop {
        let mut rx = recv_rx.lock().await;
        if let Some((data, addr)) = rx.recv().await {
            drop(rx);
            
            if let Ok(header) = bincode::deserialize::<MessageHeader>(&data[..data.len().min(32)]) {
                if header.msg_type == MessageType::Init {
                    info!("✅ 클라이언트 연결: {}", addr);

                    // 암호화 설정 (키 교환)
                    let crypto = if encrypt {
                        info!("🔐 키 교환 시작...");
                        
                        let server_keypair = EphemeralKeyPair::generate();
                        let server_public = server_keypair.public_key_bytes();
                        let key_msg = KeyExchangeMessage { public_key: server_public };
                        
                        // 클라이언트 공개키 수신 (수신 큐에서)
                        let client_key_msg = loop {
                            let _ = priority_tx.send((key_msg.to_bytes(), addr)).await;
                            
                            let mut rx = recv_rx.lock().await;
                            match tokio::time::timeout(Duration::from_millis(500), rx.recv()).await {
                                Ok(Some((data, _))) => {
                                    drop(rx);
                                    if let Some(msg) = KeyExchangeMessage::from_bytes(&data) {
                                        break msg;
                                    }
                                }
                                Ok(None) => return Err("수신 채널 종료".into()),
                                Err(_) => {
                                    drop(rx);
                                    info!("🔐 키 교환 재전송...");
                                }
                            }
                        };
                        
                        let session = CryptoSession::establish(server_keypair, client_key_msg.public_key);
                        info!("🔐 키 교환 완료!");
                        
                        Some(Arc::new(Mutex::new(session)))
                    } else {
                        None
                    };

                    break (addr, crypto);
                }
            }
        }
    };

    // InitAck 전송 (우선순위 큐)
    let ack = InitAckMessage::new(
        data.len() as u64,
        config.chunk_size as u16,
        config.segment_size as u32,
        config.base_redundancy_ratio as f32,
    );
    let _ = priority_tx.send((ack.to_bytes(), client_addr)).await;

    // 세그먼트 준비 (병렬 처리)
    let segment_builder = Arc::new(SegmentBuilder::new(config.chunk_size));
    let data = Arc::new(data);
    let total_segments = (data.len() + config.segment_size - 1) / config.segment_size;
    
    info!("🚀 전송 시작: {} 세그먼트", total_segments);

    // 세그먼트별 청크 저장 (재전송용)
    let segment_chunks: Arc<RwLock<HashMap<u64, Vec<sls::chunk::Chunk>>>> = 
        Arc::new(RwLock::new(HashMap::new()));

    // 흐름 제어 상태
    let send_delay_us = Arc::new(std::sync::atomic::AtomicU64::new(0));
    let send_delay_fc = send_delay_us.clone();
    
    // 초기 전송 완료 플래그
    let initial_send_done = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let initial_done_fc = initial_send_done.clone();
    
    // 네트워크 속도 측정용 상태
    let measured_throughput = Arc::new(std::sync::atomic::AtomicU64::new(0));
    let measured_fc = measured_throughput.clone();
    
    // 전송 세그먼트 카운터
    let segments_sent = Arc::new(std::sync::atomic::AtomicU64::new(0));
    let segments_sent_fc = segments_sent.clone();
    
    // 이동 평균 손실률
    let smoothed_loss = Arc::new(tokio::sync::Mutex::new(0.0f64));
    let smoothed_loss_fc = smoothed_loss.clone();
    let prev_sent = Arc::new(std::sync::atomic::AtomicU64::new(0));
    let prev_recv = Arc::new(std::sync::atomic::AtomicU64::new(0));
    let prev_sent_fc = prev_sent.clone();
    let prev_recv_fc = prev_recv.clone();
    
    // FlowControl 처리 태스크 (수신 큐에서 읽기)
    let fc_running = Arc::new(std::sync::atomic::AtomicBool::new(true));
    let fc_running_clone = fc_running.clone();
    let ack_bytes_fc = ack.to_bytes();
    let priority_tx_fc = priority_tx.clone();
    let recv_rx_fc = recv_rx.clone();
    
    let _fc_task = tokio::spawn(async move {
        let mut last_log = Instant::now();
        while fc_running_clone.load(std::sync::atomic::Ordering::Relaxed) {
            let mut rx = recv_rx_fc.lock().await;
            match tokio::time::timeout(Duration::from_millis(50), rx.recv()).await {
                Ok(Some((data, addr))) => {
                    drop(rx);
                    
                    // Init 재수신 → InitAck 우선순위 큐로 전송
                    if let Ok(header) = bincode::deserialize::<MessageHeader>(&data[..data.len().min(32)]) {
                        if header.msg_type == MessageType::Init {
                            let _ = priority_tx_fc.try_send((ack_bytes_fc.clone(), addr));
                            continue;
                        }
                    }
                    
                    if let Some(fc) = FlowControlMessage::from_bytes(&data) {
                        if !initial_done_fc.load(std::sync::atomic::Ordering::Relaxed) {
                            continue;
                        }
                        
                        let current_delay = send_delay_fc.load(std::sync::atomic::Ordering::Relaxed);
                        let current_throughput = measured_fc.load(std::sync::atomic::Ordering::Relaxed);
                        let throughput_mbps = current_throughput as f64 / 1_000_000.0;
                        
                        let client_segments = fc.processing_rate as u64;
                        let server_segments = segments_sent_fc.load(std::sync::atomic::Ordering::Relaxed);
                        
                        let prev_s = prev_sent_fc.load(std::sync::atomic::Ordering::Relaxed);
                        let prev_r = prev_recv_fc.load(std::sync::atomic::Ordering::Relaxed);
                        
                        let sent_delta = server_segments.saturating_sub(prev_s);
                        let recv_delta = client_segments.saturating_sub(prev_r);
                        
                        prev_sent_fc.store(server_segments, std::sync::atomic::Ordering::Relaxed);
                        prev_recv_fc.store(client_segments, std::sync::atomic::Ordering::Relaxed);
                        
                        let instant_loss = if sent_delta > 5 && recv_delta <= sent_delta {
                            (sent_delta - recv_delta) as f64 / sent_delta as f64
                        } else {
                            0.0
                        };
                        
                        let mut smoothed = smoothed_loss_fc.lock().await;
                        *smoothed = *smoothed * 0.5 + instant_loss * 0.5;
                        let loss_rate = *smoothed;
                        drop(smoothed);
                        
                        let target = 0.05;
                        let diff = loss_rate - target;
                        let multiplier = if diff < 0.0 {
                            (1.0 + diff * 8.0).max(0.6)
                        } else {
                            (1.0 + diff * 3.0).min(1.3)
                        };
                        let new_delay = ((current_delay as f64 * multiplier) as u64).clamp(10, 2000);
                        
                        send_delay_fc.store(new_delay, std::sync::atomic::Ordering::Relaxed);
                        
                        if last_log.elapsed() > Duration::from_secs(2) {
                            info!("📶 손실:{:.1}% | {:.1}MB/s | 지연:{}us", 
                                loss_rate * 100.0, throughput_mbps, new_delay);
                            last_log = Instant::now();
                        }
                    }
                }
                Ok(None) => break,
                Err(_) => { drop(rx); continue; }
            }
        }
    });
    
    // 데이터 전송
    let tx = data_tx.clone();

    let start = Instant::now();
    let mut total_chunks = 0u64;
    let mut total_redundant = 0u64;

    let _chunk_size = config.chunk_size;
    let segment_size = config.segment_size;
    let redundancy_ratio = config.base_redundancy_ratio;
    
    for segment_id in 1..=total_segments as u64 {
        let offset = (segment_id as usize - 1) * segment_size;
        let end = (offset + segment_size).min(data.len());
        let segment_data = &data[offset..end];

        let processed_data = if let Some(ref session) = crypto_session {
            let mut session = session.lock().await;
            session.encrypt(segment_id, segment_data)?
        } else {
            segment_data.to_vec()
        };

        let chunks = segment_builder.split_into_chunks(segment_id, &processed_data, 0);
        let redundant_chunks = segment_builder.create_redundant_chunks(&chunks, redundancy_ratio);

        {
            let mut cache = segment_chunks.write().await;
            cache.insert(segment_id, chunks.clone());
        }

        for chunk in &chunks {
            let bytes = chunk.to_bytes();
            let _ = tx.send((bytes, client_addr)).await;
            total_chunks += 1;
        }

        for chunk in &redundant_chunks {
            let bytes = chunk.to_bytes();
            let _ = tx.send((bytes, client_addr)).await;
            total_redundant += 1;
        }
        
        segments_sent.fetch_add(1, std::sync::atomic::Ordering::Relaxed);

        if segment_id % 100 == 0 || segment_id == total_segments as u64 {
            let progress = (segment_id as f64 / total_segments as f64) * 100.0;
            let elapsed = start.elapsed().as_secs_f64();
            let speed = end as f64 / elapsed / 1024.0 / 1024.0;
            info!("📊 진행: {:.1}% | 세그먼트 {}/{} | {:.2} MB/s", progress, segment_id, total_segments, speed);
        }
    }

    drop(tx);
    tokio::time::sleep(Duration::from_millis(100)).await;

    let elapsed = start.elapsed();
    let throughput = data.len() as f64 / elapsed.as_secs_f64() / 1024.0 / 1024.0;

    info!("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");
    info!("✅ 1차 전송 완료!");
    info!("   시간: {:.2}s", elapsed.as_secs_f64());
    info!("   총 청크: {} (원본) + {} (중복)", total_chunks, total_redundant);
    info!("   처리량: {:.2} MB/s", throughput);
    if encrypt {
        info!("   암호화: ChaCha20-Poly1305");
    }
    info!("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");

    initial_send_done.store(true, std::sync::atomic::Ordering::Relaxed);
    send_delay_us.store(0, std::sync::atomic::Ordering::Relaxed);

    // NACK 처리
    let nack_wait_secs = ((data.len() as u64 / (5 * 1024 * 1024)) + 60).max(120);
    info!("⏳ NACK 대기 및 재전송 중 (최대 {}초)...", nack_wait_secs);
    
    let retransmit_count = Arc::new(std::sync::atomic::AtomicU64::new(0));
    let last_nack_time = Arc::new(tokio::sync::RwLock::new(Instant::now()));
    let completed_segments: Arc<tokio::sync::RwLock<std::collections::HashSet<u64>>> = 
        Arc::new(tokio::sync::RwLock::new(std::collections::HashSet::new()));
    let nack_running = Arc::new(std::sync::atomic::AtomicBool::new(true));
    
    let (nack_tx, nack_rx) = mpsc::channel::<NackMessage>(10000);
    let nack_rx = Arc::new(tokio::sync::Mutex::new(nack_rx));
    
    // NACK 처리 태스크 (수신 큐에서 읽기)
    let recv_running = nack_running.clone();
    let recv_last_nack = last_nack_time.clone();
    let recv_completed = completed_segments.clone();
    let recv_delay = send_delay_us.clone();
    let ack_bytes = ack.to_bytes();
    let priority_tx_nack = priority_tx.clone();
    let recv_rx_nack = recv_rx.clone();
    
    let nack_recv_task = tokio::spawn(async move {
        while recv_running.load(std::sync::atomic::Ordering::Relaxed) {
            let mut rx = recv_rx_nack.lock().await;
            match tokio::time::timeout(Duration::from_millis(10), rx.recv()).await {
                Ok(Some((data, addr))) => {
                    drop(rx);
                    
                    if let Ok(header) = bincode::deserialize::<MessageHeader>(&data[..data.len().min(32)]) {
                        match header.msg_type {
                            MessageType::Init => {
                                let _ = priority_tx_nack.try_send((ack_bytes.clone(), addr));
                            }
                            MessageType::SegmentComplete => {
                                if data.len() > 20 {
                                    if let Ok(seg_id) = bincode::deserialize::<u64>(&data[16..24]) {
                                        recv_completed.write().await.insert(seg_id);
                                    }
                                }
                            }
                            _ => {}
                        }
                    }
                    
                    if let Some(_fc) = FlowControlMessage::from_bytes(&data) {
                        let current_delay = recv_delay.load(std::sync::atomic::Ordering::Relaxed);
                        let new_delay = ((current_delay as f64 * 0.95) as u64).max(50);
                        recv_delay.store(new_delay, std::sync::atomic::Ordering::Relaxed);
                    }
                    
                    if let Some(nack) = NackMessage::from_bytes(&data) {
                        *recv_last_nack.write().await = Instant::now();
                        let _ = nack_tx.try_send(nack);
                    }
                }
                Ok(None) => break,
                Err(_) => { drop(rx); continue; }
            }
        }
    });
    
    let send_count = retransmit_count.clone();
    let num_process_workers = 4;
    let mut process_handles = Vec::new();
    
    for _worker_id in 0..num_process_workers {
        let rx = nack_rx.clone();
        let chunks_cache = segment_chunks.clone();
        let tx = data_tx.clone();
        let worker_running = nack_running.clone();
        let send_counter = send_count.clone();
        
        let handle = tokio::spawn(async move {
            loop {
                let nack = {
                    let mut rx_guard = rx.lock().await;
                    match tokio::time::timeout(Duration::from_millis(50), rx_guard.recv()).await {
                        Ok(Some(nack)) => nack,
                        Ok(None) => break,
                        Err(_) => {
                            if !worker_running.load(std::sync::atomic::Ordering::Relaxed) {
                                break;
                            }
                            continue;
                        }
                    }
                };
                
                let cache = chunks_cache.read().await;
                if let Some(chunks) = cache.get(&nack.segment_id) {
                    for &chunk_id in &nack.missing_chunk_ids {
                        if let Some(chunk) = chunks.get(chunk_id as usize) {
                            let bytes = chunk.to_bytes();
                            let _ = tx.send((bytes, client_addr)).await;
                            send_counter.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                        }
                    }
                }
            }
        });
        process_handles.push(handle);
    }
    
    // 모니터링 루프
    let nack_start = Instant::now();
    let mut last_log_time = Instant::now();
    
    loop {
        tokio::time::sleep(Duration::from_millis(100)).await;
        
        let last_nack = *last_nack_time.read().await;
        let completed_count = completed_segments.read().await.len();
        let retrans = retransmit_count.load(std::sync::atomic::Ordering::Relaxed);
        
        if last_log_time.elapsed() > Duration::from_secs(2) && retrans > 0 {
            info!("📨 재전송 진행: {} 청크 | 완료: {}/{}", retrans, completed_count, total_segments);
            last_log_time = Instant::now();
        }
        
        if last_nack.elapsed() > Duration::from_secs(30) && retrans > 0 {
            info!("⏱️  30초간 NACK 없음, 전송 완료로 간주");
            break;
        }
        
        if completed_count >= total_segments {
            info!("✅ 모든 세그먼트 완료 확인!");
            break;
        }
        
        if nack_start.elapsed() > Duration::from_secs(nack_wait_secs) {
            info!("⏱️  NACK 대기 시간 초과");
            break;
        }
    }
    
    nack_running.store(false, std::sync::atomic::Ordering::Relaxed);
    fc_running.store(false, std::sync::atomic::Ordering::Relaxed);
    let _ = nack_recv_task.await;
    for handle in process_handles {
        let _ = handle.await;
    }
    
    let final_retrans = retransmit_count.load(std::sync::atomic::Ordering::Relaxed);
    let final_completed = completed_segments.read().await.len();

    info!("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");
    info!("🏁 서버 종료");
    info!("   총 재전송: {} 청크", final_retrans);
    info!("   완료 세그먼트: {}/{}", final_completed, total_segments);
    info!("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");

    Ok(())
}

/// 클라이언트 (수신자) 실행 - 병렬 처리 + 암호화 지원
/// 
/// 서버 주소만 지정하면 나머지 설정은 InitAck에서 수신
async fn run_client(
    server_addr: SocketAddr,
    encrypt: bool,
) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    info!("📡 클라이언트 시작");
    info!("🎯 서버: {}", server_addr);
    info!("⚙️  암호화: {}", if encrypt { "✅ 활성화" } else { "❌ 비활성화" });

    // 소켓 생성
    let socket = Arc::new(UdpSocket::bind("0.0.0.0:0").await?);

    // ═══════════════════════════════════════════════════════════════
    // 단일 송신 큐 + 송신 태스크 (모든 전송은 이 큐를 통해)
    // ═══════════════════════════════════════════════════════════════
    let (send_tx, mut send_rx) = mpsc::channel::<Vec<u8>>(1000);
    
    let send_socket = socket.clone();
    let _send_task = tokio::spawn(async move {
        while let Some(bytes) = send_rx.recv().await {
            let _ = send_socket.send_to(&bytes, server_addr).await;
        }
    });

    // ═══════════════════════════════════════════════════════════════
    // 단일 수신 큐 + 수신 태스크 (모든 수신은 이 큐를 통해)
    // ═══════════════════════════════════════════════════════════════
    let (recv_tx, recv_rx) = mpsc::channel::<Vec<u8>>(100_000);
    let recv_rx = Arc::new(tokio::sync::Mutex::new(recv_rx));
    
    let recv_socket = socket.clone();
    let _recv_task = tokio::spawn(async move {
        let mut buf = vec![0u8; 2048];
        loop {
            match recv_socket.recv_from(&mut buf).await {
                Ok((len, _)) => {
                    let _ = recv_tx.try_send(buf[..len].to_vec());
                }
                Err(_) => break,
            }
        }
    });

    // ═══════════════════════════════════════════════════════════════
    // Init/InitAck 핸드쉐이크 (수신 큐에서 읽기)
    // ═══════════════════════════════════════════════════════════════
    let init_msg = sls::message::InitMessage::new(encrypt, [0u8; 32]);
    let retry_interval = Duration::from_millis(500);
    let max_retries = 20;
    let mut retry_count = 0;
    
    info!("📤 Init 전송 (서버 응답 대기 중)...");
    
    let (init_ack, crypto_session): (sls::message::InitAckMessage, Option<Arc<Mutex<CryptoSession>>>) = loop {
        // Init 전송 (송신 큐 사용)
        let _ = send_tx.send(init_msg.to_bytes()).await;
        
        if retry_count > 0 && retry_count % 4 == 0 {
            info!("📤 Init 재전송 #{} ({}초 경과)...", retry_count, retry_count as f32 * 0.5);
        }
        
        // 수신 큐에서 읽기 (타임아웃 적용)
        let mut rx = recv_rx.lock().await;
        match tokio::time::timeout(retry_interval, rx.recv()).await {
            Ok(Some(data)) => {
                drop(rx);  // 락 해제
                
                if let Some(ack) = sls::message::InitAckMessage::from_bytes(&data) {
                    break (ack, None);
                }
                
                if encrypt {
                    if let Some(server_key_msg) = KeyExchangeMessage::from_bytes(&data) {
                        info!("🔑 서버 공개키 수신 완료");
                        
                        let client_keypair = EphemeralKeyPair::generate();
                        let client_public = client_keypair.public_key_bytes();
                        let key_msg = KeyExchangeMessage { public_key: client_public };
                        let _ = send_tx.send(key_msg.to_bytes()).await;
                        info!("🔑 클라이언트 공개키 전송 완료");
                        
                        let session = CryptoSession::establish(client_keypair, server_key_msg.public_key);
                        info!("🔐 키 교환 완료!");
                        let crypto = Some(Arc::new(Mutex::new(session)));
                        
                        // InitAck 대기
                        let ack = loop {
                            let mut rx = recv_rx.lock().await;
                            match tokio::time::timeout(retry_interval, rx.recv()).await {
                                Ok(Some(data)) => {
                                    drop(rx);
                                    if let Some(ack) = sls::message::InitAckMessage::from_bytes(&data) {
                                        break ack;
                                    }
                                }
                                Ok(None) => return Err("수신 채널 종료".into()),
                                Err(_) => {
                                    drop(rx);
                                    let _ = send_tx.send(init_msg.to_bytes()).await;
                                }
                            }
                        };
                        break (ack, crypto);
                    }
                }
            }
            Ok(None) => return Err("수신 채널 종료".into()),
            Err(_) => {
                drop(rx);  // 락 해제 후 재시도
            }
        }
        
        retry_count += 1;
        if retry_count >= max_retries {
            return Err("서버 응답 타임아웃 (10초) - 서버가 실행 중인지 확인하세요".into());
        }
    };
    
    info!("✅ InitAck 수신 완료 (시도: {}회)", retry_count + 1);
    
    // 서버에서 받은 설정 정보
    let total_file_size = init_ack.total_file_size as usize;
    let expected_segments = init_ack.total_segments as usize;
    let segment_size = init_ack.segment_size as usize;
    let chunk_size = init_ack.chunk_size as usize;
    let chunks_per_segment = init_ack.chunks_per_segment as usize;
    
    info!("✅ InitAck 수신 완료:");
    info!("   파일 크기: {} bytes ({:.2} MB)", total_file_size, total_file_size as f64 / 1024.0 / 1024.0);
    info!("   총 세그먼트: {}", expected_segments);
    info!("   세그먼트 크기: {} bytes", segment_size);
    info!("   청크 크기: {} bytes", chunk_size);
    info!("   세그먼트당 청크: {}", chunks_per_segment);
    
    info!("✅ 서버 연결 완료, 데이터 수신 시작...");

    let start = Instant::now();
    
    // ═══════════════════════════════════════════════════════════════
    // 병렬 파이프라인 구조:
    // [수신 태스크(시작 시 생성됨)] → recv_rx → [처리 워커 풀] → assembled_channel → [조립 태스크]
    // ═══════════════════════════════════════════════════════════════
    
    // 공유 상태 (락 기반)
    let segment_chunks: Arc<tokio::sync::RwLock<HashMap<u64, HashMap<u32, Vec<u8>>>>> = 
        Arc::new(tokio::sync::RwLock::new(HashMap::new()));
    let segment_total_chunks: Arc<tokio::sync::RwLock<HashMap<u64, u32>>> = 
        Arc::new(tokio::sync::RwLock::new(HashMap::new()));
    let assembled_segments: Arc<tokio::sync::RwLock<std::collections::HashSet<u64>>> = 
        Arc::new(tokio::sync::RwLock::new(std::collections::HashSet::new()));
    
    // 통계 (atomic)
    let total_chunks_received = Arc::new(std::sync::atomic::AtomicU64::new(0));
    let last_chunk_time = Arc::new(tokio::sync::RwLock::new(Instant::now()));
    
    // 채널들 (수신 큐는 이미 생성됨, 조립용 채널만 생성)
    let (assembled_tx, mut assembled_rx) = mpsc::channel::<(u64, Vec<u8>)>(1000);
    
    // 최종 결과 저장소
    let decrypted_segments: Arc<Mutex<HashMap<u64, Vec<u8>>>> = Arc::new(Mutex::new(HashMap::new()));
    
    // 종료 플래그
    let running = Arc::new(std::sync::atomic::AtomicBool::new(true));
    
    // ─────────────────────────────────────────────────────────────────
    // 처리 워커 풀 (파싱 + 중복검사 + 저장 + 세그먼트 완료 체크)
    // 수신 태스크는 이미 시작됨, 여기서는 recv_rx에서 읽기만
    // ─────────────────────────────────────────────────────────────────
    let num_workers = 4;
    let mut worker_handles = Vec::new();
    
    for _worker_id in 0..num_workers {
        let rx = recv_rx.clone();
        let last_chunk = last_chunk_time.clone();
        let chunks = segment_chunks.clone();
        let totals = segment_total_chunks.clone();
        let assembled = assembled_segments.clone();
        let assembled_tx = assembled_tx.clone();
        let chunks_count = total_chunks_received.clone();
        let worker_running = running.clone();
        
        let handle = tokio::spawn(async move {
            loop {
                let data = {
                    let mut rx_guard = rx.lock().await;
                    match tokio::time::timeout(Duration::from_millis(50), rx_guard.recv()).await {
                        Ok(Some(data)) => data,
                        Ok(None) => break,  // 채널 닫힘
                        Err(_) => {
                            if !worker_running.load(std::sync::atomic::Ordering::Relaxed) {
                                break;
                            }
                            continue;
                        }
                    }
                };
                
                // 마지막 수신 시간 업데이트
                *last_chunk.write().await = Instant::now();
                
                // 청크 파싱
                if let Some(chunk) = sls::chunk::Chunk::from_bytes(&data) {
                    let segment_id = chunk.header.segment_id;
                    let chunk_id = chunk.header.chunk_id;
                    let total_chunks = chunk.header.total_chunks;
                    
                    // 총 청크 수 저장
                    totals.write().await.insert(segment_id, total_chunks);
                    
                    // 청크 저장 (중복 검사 포함)
                    let mut chunks_guard = chunks.write().await;
                    let segment = chunks_guard.entry(segment_id).or_insert_with(HashMap::new);
                    if !segment.contains_key(&chunk_id) {
                        segment.insert(chunk_id, chunk.data.to_vec());
                        chunks_count.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                    }
                    
                    // 세그먼트 완료 체크
                    let is_complete = segment.len() >= total_chunks as usize;
                    let already_assembled = assembled.read().await.contains(&segment_id);
                    
                    if is_complete && !already_assembled {
                        // 청크 순서대로 조립
                        let mut segment_data = Vec::with_capacity(total_chunks as usize * 1200);
                        for i in 0..total_chunks {
                            if let Some(chunk_data) = segment.get(&i) {
                                segment_data.extend_from_slice(chunk_data);
                            }
                        }
                        
                        drop(chunks_guard);  // 락 해제
                        
                        assembled.write().await.insert(segment_id);
                        let _ = assembled_tx.try_send((segment_id, segment_data));
                    }
                }
            }
        });
        worker_handles.push(handle);
    }
    drop(assembled_tx);  // 워커들만 보유하도록
    
    // ─────────────────────────────────────────────────────────────────
    // 3. 조립/복호화 태스크
    // ─────────────────────────────────────────────────────────────────
    let decrypt_segments = decrypted_segments.clone();
    let crypto = crypto_session.clone();
    let assemble_task = tokio::spawn(async move {
        while let Some((segment_id, segment_data)) = assembled_rx.recv().await {
            let final_data = if encrypt {
                if let Some(ref session) = crypto {
                    let session = session.lock().await;
                    session.decrypt(&segment_data).unwrap_or(segment_data)
                } else {
                    segment_data
                }
            } else {
                segment_data
            };
            decrypt_segments.lock().await.insert(segment_id, final_data);
        }
    });
    
    // ─────────────────────────────────────────────────────────────────
    // 4. 모니터링 + NACK + FlowControl 루프 (메인 스레드)
    // ─────────────────────────────────────────────────────────────────
    let mut nack_count = 0u64;
    let mut last_progress_time = Instant::now();
    let mut flow_control_time = Instant::now();
    
    loop {
        tokio::time::sleep(Duration::from_millis(100)).await;
        
        let assembled_count = assembled_segments.read().await.len();
        let last_chunk = *last_chunk_time.read().await;
        
        // 진행률 표시 (0.5초마다)
        if last_progress_time.elapsed() > Duration::from_millis(500) {
            let progress = (assembled_count as f64 / expected_segments as f64) * 100.0;
            let elapsed = start.elapsed().as_secs_f64();
            let total_bytes = assembled_count * segment_size;
            let speed = total_bytes as f64 / elapsed / 1024.0 / 1024.0;
            info!(
                "📊 수신: {:.1}% | 세그먼트 {}/{} | {:.2} MB | {:.2} MB/s",
                progress.min(100.0), assembled_count, expected_segments, 
                total_bytes as f64 / 1024.0 / 1024.0, speed
            );
            last_progress_time = Instant::now();
        }
        
        // 흐름 제어 메시지 전송 (100ms마다)
        if flow_control_time.elapsed() > Duration::from_millis(100) {
            let chunks_map = segment_chunks.read().await;
            let assembled_set = assembled_segments.read().await;
            let incomplete_segments = chunks_map.len() - assembled_set.len();
            
            let fc = FlowControlMessage::new(
                assembled_set.len() as u32,
                assembled_set.iter().max().copied().unwrap_or(0),
                incomplete_segments as u32,
                0.0,
                assembled_set.len() as f32,
            );
            let _ = send_tx.try_send(fc.to_bytes());
            flow_control_time = Instant::now();
        }
        
        // 완료 체크
        if assembled_count >= expected_segments {
            info!("📦 모든 세그먼트 수신 완료");
            break;
        }
        
        // NACK 전송 (데이터가 잠시 안오면)
        if last_chunk.elapsed() > Duration::from_millis(200) {
            let chunks_map = segment_chunks.read().await;
            let totals_map = segment_total_chunks.read().await;
            let assembled_set = assembled_segments.read().await;
            
            let mut nacks_sent = 0;
            let mut total_chunks_requested = 0u64;
            
            // 1. 부분적으로 받은 세그먼트의 누락 청크 요청
            for (segment_id, chunks) in chunks_map.iter() {
                if !assembled_set.contains(segment_id) {
                    let total_chunks = totals_map.get(segment_id).copied().unwrap_or(55);
                    let received: std::collections::HashSet<u32> = chunks.keys().copied().collect();
                    let missing: Vec<u32> = (0..total_chunks)
                        .filter(|i| !received.contains(i))
                        .collect();
                    
                    if !missing.is_empty() {
                        total_chunks_requested += missing.len() as u64;
                        let nack = NackMessage::new(*segment_id, missing.clone(), 0.0, 0);
                        let _ = send_tx.try_send(nack.to_bytes());
                        nack_count += 1;
                        nacks_sent += 1;
                        
                        if nacks_sent >= 50 {
                            break;
                        }
                    }
                }
            }
            
            // 2. 아예 청크를 하나도 못 받은 세그먼트 요청 (전체 세그먼트 요청)
            if nacks_sent < 50 {
                for seg_id in 1..=expected_segments as u64 {
                    if !assembled_set.contains(&seg_id) && !chunks_map.contains_key(&seg_id) {
                        // 전체 청크 요청
                        let all_chunks: Vec<u32> = (0..chunks_per_segment as u32).collect();
                        total_chunks_requested += chunks_per_segment as u64;
                        let nack = NackMessage::new(seg_id, all_chunks, 0.0, 0);
                        let _ = send_tx.try_send(nack.to_bytes());
                        nack_count += 1;
                        nacks_sent += 1;
                        
                        if nacks_sent >= 50 {
                            break;
                        }
                    }
                }
            }
            
            if nacks_sent > 0 {
                info!("📨 NACK: {}개 세그먼트 / {}개 청크 요청", nacks_sent, total_chunks_requested);
            }
        }
        
        // 10초간 새 데이터 없고 95% 이상 받았으면 종료
        if last_chunk.elapsed() > Duration::from_secs(10) {
            let progress = assembled_count as f64 / expected_segments as f64;
            if progress >= 0.95 {
                info!("✅ 95% 이상 수신 완료, 종료");
                break;
            }
        }
        
        // 60초간 새 데이터 없으면 종료
        if last_chunk.elapsed() > Duration::from_secs(60) {
            info!("⏱️  60초간 새 데이터 없음, 종료");
            break;
        }
        
        // 전체 타임아웃
        let total_timeout_secs = ((total_file_size as u64 / (3 * 1024 * 1024)) + 120).max(180);
        if start.elapsed() > Duration::from_secs(total_timeout_secs) {
            info!("⏱️  전체 타임아웃 ({}초)", total_timeout_secs);
            break;
        }
    }

    // 파이프라인 종료
    running.store(false, std::sync::atomic::Ordering::Relaxed);
    for handle in worker_handles {
        let _ = handle.await;
    }
    let _ = assemble_task.await;

    // 세그먼트 순서대로 조립
    let final_segments = decrypted_segments.lock().await;
    let mut received_data = Vec::with_capacity(total_file_size);
    let mut sorted_ids: Vec<u64> = final_segments.keys().copied().collect();
    sorted_ids.sort();
    
    for segment_id in sorted_ids {
        if let Some(data) = final_segments.get(&segment_id) {
            received_data.extend_from_slice(data);
        }
    }

    let elapsed = start.elapsed();
    let throughput = received_data.len() as f64 / elapsed.as_secs_f64() / 1024.0 / 1024.0;

    // 실제 전송 성공률 계산
    let success_rate = if total_file_size > 0 {
        (received_data.len() as f64 / total_file_size as f64 * 100.0).min(100.0)
    } else {
        0.0
    };

    info!("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");
    info!("✅ 수신 완료!");
    info!("   시간: {:.2}s", elapsed.as_secs_f64());
    info!("   세그먼트: {}/{}", final_segments.len(), expected_segments);
    info!("   청크: {}", total_chunks_received.load(std::sync::atomic::Ordering::Relaxed));
    info!("   수신 크기: {:.2} MB / {:.2} MB", 
        received_data.len() as f64 / 1024.0 / 1024.0,
        total_file_size as f64 / 1024.0 / 1024.0);
    info!("   전송 성공률: {:.2}%", success_rate);
    info!("   처리량: {:.2} MB/s", throughput);
    info!("   NACK 전송 횟수: {}", nack_count);
    if encrypt {
        info!("   암호화: ChaCha20-Poly1305");
    }
    info!("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");

    Ok(received_data)
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // 로깅 설정
    let subscriber = FmtSubscriber::builder()
        .with_max_level(Level::INFO)
        .with_target(false)
        .finish();
    tracing::subscriber::set_global_default(subscriber)?;

    let args: Vec<String> = std::env::args().collect();

    let mut size_mb = 10usize;
    let mut is_server = false;
    let mut is_client = false;
    let mut addr: SocketAddr = "127.0.0.1:9000".parse()?;
    let mut encrypt = false;
    let mut num_workers = num_cpus();

    let mut i = 1;
    while i < args.len() {
        match args[i].as_str() {
            "--size" => {
                if i + 1 < args.len() {
                    size_mb = args[i + 1].parse()?;
                    i += 1;
                }
            }
            "--server" => is_server = true,
            "--client" => is_client = true,
            "--addr" | "--bind" | "-b" => {
                if i + 1 < args.len() {
                    addr = args[i + 1].parse()?;
                    i += 1;
                }
            }
            "--encrypt" | "-e" => encrypt = true,
            "--workers" | "-w" => {
                if i + 1 < args.len() {
                    num_workers = args[i + 1].parse()?;
                    i += 1;
                }
            }
            "--help" | "-h" => {
                println!(r#"
대용량 파일 전송 테스트 (병렬 처리 + 암호화 지원)

사용법:
  cargo run --release --example large_file_test -- [OPTIONS]

옵션:
  --size <MB>       테스트 데이터 크기 (MB, 기본: 10)
  --server          서버 모드로 실행
  --client          클라이언트 모드로 실행  
  --bind, -b <ADDR> 서버: 바인드 주소 / 클라이언트: 서버 주소 (기본: 127.0.0.1:9000)
  --encrypt, -e     암호화 활성화 (X25519 + ChaCha20-Poly1305)
  --workers <N>     병렬 워커 수 (기본: CPU 코어 수)

예시:
  # 서버 (외부 접속 허용)
  cargo run --release --example large_file_test -- --server --size 100 --bind 0.0.0.0:9000

  # 클라이언트 (원격 서버 접속)
  cargo run --release --example large_file_test -- --client --size 100 --bind 192.168.1.100:9000

  # 암호화 전송
  cargo run --release --example large_file_test -- --server --size 100 --encrypt --bind 0.0.0.0:9000
  cargo run --release --example large_file_test -- --client --size 100 --encrypt --bind 192.168.1.100:9000
"#);
                return Ok(());
            }
            _ => {}
        }
        i += 1;
    }

    // 설정
    let mut config = Config::default();
    config.chunk_size = 1200;
    config.segment_size = 65536;  // 64KB
    config.base_redundancy_ratio = 0.20;  // 20% 중복
    config.nack_timeout_ms = 100;  // NACK 체크 주기
    config.segment_timeout_ms = 30000;  // 30초 세그먼트 타임아웃
    config.encryption_enabled = encrypt;
    config.parallel_workers = num_workers;

    let data_size = size_mb * 1024 * 1024;

    if is_server {
        // 서버 모드
        info!("═══════════════════════════════════════════");
        info!("  SLS 대용량 전송 테스트 - 서버");
        if encrypt {
            info!("  🔐 암호화: X25519 + ChaCha20-Poly1305");
        }
        info!("═══════════════════════════════════════════");

        let data = generate_test_text(size_mb);
        run_server(addr, data, config, encrypt, num_workers).await?;

    } else if is_client {
        // 클라이언트 모드
        info!("═══════════════════════════════════════════");
        info!("  SLS 대용량 전송 테스트 - 클라이언트");
        if encrypt {
            info!("  🔐 암호화: X25519 + ChaCha20-Poly1305");
        }
        info!("═══════════════════════════════════════════");

        let received = run_client(addr, encrypt).await?;

        // 데이터 일부 출력 (확인용)
        if !received.is_empty() {
            let preview_len = received.len().min(500);
            if let Ok(preview) = std::str::from_utf8(&received[..preview_len]) {
                info!("📝 수신 데이터 미리보기 (처음 {}자):", preview_len);
                for line in preview.lines().take(5) {
                    info!("   {}", line);
                }
            }
        }

    } else {
        // 둘 다 아니면 도움말 출력
        println!("--server 또는 --client 옵션을 지정하세요. --help로 도움말 확인.");
    }

    Ok(())
}

/// CPU 코어 수 반환
fn num_cpus() -> usize {
    std::thread::available_parallelism()
        .map(|n| n.get())
        .unwrap_or(4)
}
