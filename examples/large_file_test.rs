//! 대용량 파일 전송 테스트 (병렬 처리 + 암호화 지원)
//!
//! 사용법:
//!   cargo run --release --example large_file_test -- [OPTIONS]
//!
//! 옵션:
//!   --size <MB>       테스트 데이터 크기 (MB, 기본: 10)
//!   --server          서버 모드로 실행
//!   --client          클라이언트 모드로 실행
//!   --bind, -b <ADDR> 서버/클라이언트 주소 (기본: 127.0.0.1:9000)
//!   --encrypt, -e     암호화 활성화 (X25519 + ChaCha20-Poly1305)
//!   --workers <N>     병렬 워커 수 (기본: CPU 코어 수)

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
    num_workers: usize,
) -> Result<(), Box<dyn std::error::Error>> {
    let socket = Arc::new(UdpSocket::bind(addr).await?);
    info!("📡 서버 시작: {}", addr);
    info!("📦 전송 데이터: {} bytes ({:.2} MB)", data.len(), data.len() as f64 / 1024.0 / 1024.0);
    info!("⚙️  청크 크기: {} bytes", config.chunk_size);
    info!("⚙️  세그먼트 크기: {} bytes", config.segment_size);
    info!("⚙️  중복률: {:.1}%", config.base_redundancy_ratio * 100.0);
    info!("⚙️  암호화: {}", if encrypt { "✅ 활성화" } else { "❌ 비활성화" });
    info!("⚙️  병렬 워커: {}", num_workers);

    // 클라이언트 연결 대기
    let mut buf = vec![0u8; 65535];
    info!("⏳ 클라이언트 연결 대기 중...");

    loop {
        let (len, client_addr) = socket.recv_from(&mut buf).await?;

        if let Ok(header) = bincode::deserialize::<MessageHeader>(&buf[..len.min(32)]) {
            if header.msg_type == MessageType::Init {
                info!("✅ 클라이언트 연결: {}", client_addr);

                // 암호화 설정
                let crypto_session: Option<Arc<Mutex<CryptoSession>>> = if encrypt {
                    info!("🔐 키 교환 시작...");
                    
                    // 서버 키쌍 생성
                    let server_keypair = EphemeralKeyPair::generate();
                    let server_public = server_keypair.public_key_bytes();
                    
                    // 서버 공개키 전송
                    let key_msg = KeyExchangeMessage { public_key: server_public };
                    socket.send_to(&key_msg.to_bytes(), client_addr).await?;
                    
                    // 클라이언트 공개키 수신
                    let (len, _) = socket.recv_from(&mut buf).await?;
                    let client_key_msg = KeyExchangeMessage::from_bytes(&buf[..len])
                        .ok_or("키 교환 실패")?;
                    
                    // 세션 생성
                    let session = CryptoSession::establish(server_keypair, client_key_msg.public_key);
                    info!("🔐 키 교환 완료!");
                    
                    Some(Arc::new(Mutex::new(session)))
                } else {
                    None
                };

                // InitAck 전송
                let ack = InitAckMessage {
                    nic_count: 1,
                    chunk_size: config.chunk_size as u16,
                    segment_size: config.segment_size as u32,
                    redundancy_ratio: config.base_redundancy_ratio as f32,
                };
                socket.send_to(&ack.to_bytes(), client_addr).await?;

                // 세그먼트 준비 (병렬 처리)
                let segment_builder = Arc::new(SegmentBuilder::new(config.chunk_size));
                let data = Arc::new(data);
                let total_segments = (data.len() + config.segment_size - 1) / config.segment_size;
                
                info!("🚀 전송 시작: {} 세그먼트 ({} 워커 병렬)", total_segments, num_workers);

                // 세그먼트별 청크 저장 (재전송용)
                let segment_chunks: Arc<RwLock<HashMap<u64, Vec<sls::chunk::Chunk>>>> = 
                    Arc::new(RwLock::new(HashMap::new()));

                // 흐름 제어 상태
                // 초기 전송: 지연 없음 (최대 속도)
                // NACK 재전송 시에만 flow control 적용
                let send_delay_us = Arc::new(std::sync::atomic::AtomicU64::new(0));
                let send_delay_clone = send_delay_us.clone();
                let send_delay_fc = send_delay_us.clone();
                
                // 초기 전송 완료 플래그
                let initial_send_done = Arc::new(std::sync::atomic::AtomicBool::new(false));
                let initial_done_fc = initial_send_done.clone();
                
                // 네트워크 속도 측정용 상태
                let measured_throughput = Arc::new(std::sync::atomic::AtomicU64::new(0)); // bytes/sec
                let measured_clone = measured_throughput.clone();
                let measured_fc = measured_throughput.clone();
                
                // 전송 세그먼트 카운터 (손실률 계산용)
                let segments_sent = Arc::new(std::sync::atomic::AtomicU64::new(0));
                let segments_sent_fc = segments_sent.clone();
                
                // 이동 평균 손실률 (smoothing)
                let smoothed_loss = Arc::new(tokio::sync::Mutex::new(0.0f64));
                let smoothed_loss_fc = smoothed_loss.clone();
                let prev_sent = Arc::new(std::sync::atomic::AtomicU64::new(0));
                let prev_recv = Arc::new(std::sync::atomic::AtomicU64::new(0));
                let prev_sent_fc = prev_sent.clone();
                let prev_recv_fc = prev_recv.clone();
                
                // FlowControl 수신 태스크 (전송 중에도 실시간 조절)
                let fc_socket = socket.clone();
                let fc_running = Arc::new(std::sync::atomic::AtomicBool::new(true));
                let fc_running_clone = fc_running.clone();
                
                let _fc_task = tokio::spawn(async move {
                    let mut buf = vec![0u8; 256];
                    let mut last_log = Instant::now();
                    while fc_running_clone.load(std::sync::atomic::Ordering::Relaxed) {
                        match tokio::time::timeout(Duration::from_millis(50), fc_socket.recv_from(&mut buf)).await {
                            Ok(Ok((len, _))) => {
                                if let Some(fc) = FlowControlMessage::from_bytes(&buf[..len]) {
                                    // 초기 전송 중에는 flow control 무시
                                    if !initial_done_fc.load(std::sync::atomic::Ordering::Relaxed) {
                                        continue;
                                    }
                                    
                                    let current_delay = send_delay_fc.load(std::sync::atomic::Ordering::Relaxed);
                                    let current_throughput = measured_fc.load(std::sync::atomic::Ordering::Relaxed);
                                    let throughput_mbps = current_throughput as f64 / 1_000_000.0;
                                    
                                    // 현재 값 (세그먼트 단위)
                                    let client_segments = fc.processing_rate as u64;
                                    let server_segments = segments_sent_fc.load(std::sync::atomic::Ordering::Relaxed);
                                    
                                    // 이전 값
                                    let prev_s = prev_sent_fc.load(std::sync::atomic::Ordering::Relaxed);
                                    let prev_r = prev_recv_fc.load(std::sync::atomic::Ordering::Relaxed);
                                    
                                    // 델타 계산 (세그먼트 단위)
                                    let sent_delta = server_segments.saturating_sub(prev_s);
                                    let recv_delta = client_segments.saturating_sub(prev_r);
                                    
                                    // 이전 값 업데이트
                                    prev_sent_fc.store(server_segments, std::sync::atomic::Ordering::Relaxed);
                                    prev_recv_fc.store(client_segments, std::sync::atomic::Ordering::Relaxed);
                                    
                                    // 순간 손실률 (세그먼트 기준, 최소 5개 이상일 때 계산)
                                    let instant_loss = if sent_delta > 5 && recv_delta <= sent_delta {
                                        (sent_delta - recv_delta) as f64 / sent_delta as f64
                                    } else {
                                        0.0
                                    };
                                    
                                    // 이동 평균 (alpha = 0.5, 빠른 반응)
                                    let mut smoothed = smoothed_loss_fc.lock().await;
                                    *smoothed = *smoothed * 0.5 + instant_loss * 0.5;
                                    let loss_rate = *smoothed;
                                    drop(smoothed);
                                    
                                    // 손실률 5% 목표 - 비대칭 수식
                                    // 빨라짐: 더 공격적 (sensitivity 8)
                                    // 느려짐: 점진적 (sensitivity 3)
                                    let target = 0.05;
                                    let diff = loss_rate - target;
                                    let multiplier = if diff < 0.0 {
                                        // 빨라짐: 0% → 0.6, 2.5% → 0.8, 5% → 1.0
                                        (1.0 + diff * 8.0).max(0.6)
                                    } else {
                                        // 느려짐: 5% → 1.0, 10% → 1.15, 15% → 1.3
                                        (1.0 + diff * 3.0).min(1.3)
                                    };
                                    let new_delay = ((current_delay as f64 * multiplier) as u64).clamp(10, 2000);
                                    
                                    send_delay_fc.store(new_delay, std::sync::atomic::Ordering::Relaxed);
                                    
                                    // 2초마다 로그
                                    if last_log.elapsed() > Duration::from_secs(2) {
                                        info!("📶 손실:{:.1}% | {:.1}MB/s | 지연:{}us", 
                                            loss_rate * 100.0, throughput_mbps, new_delay);
                                        last_log = Instant::now();
                                    }
                                }
                            }
                            _ => {}
                        }
                    }
                });
                
                // 대용량 전송 채널
                let (tx, mut rx) = mpsc::channel::<Vec<u8>>(100000);

                // 고속 전송 워커 (흐름 제어 기반)
                let socket_clone = socket.clone();
                
                let send_task = tokio::spawn(async move {
                    let mut total_sent = 0u64;
                    let mut bytes_sent_window = 0u64;
                    let mut window_start = Instant::now();
                    
                    while let Some(packet) = rx.recv().await {
                        let packet_len = packet.len() as u64;
                        let _ = socket_clone.send_to(&packet, client_addr).await;
                        total_sent += 1;
                        bytes_sent_window += packet_len;
                        
                        // (세그먼트 카운터는 세그먼트 완료 시 증가)
                        
                        // 1초마다 실제 처리량 측정
                        if window_start.elapsed() >= Duration::from_secs(1) {
                            let throughput = bytes_sent_window;
                            measured_clone.store(throughput, std::sync::atomic::Ordering::Relaxed);
                            bytes_sent_window = 0;
                            window_start = Instant::now();
                        }
                        
                        // 동적 지연 적용
                        let delay = send_delay_clone.load(std::sync::atomic::Ordering::Relaxed);
                        if delay > 0 {
                            tokio::time::sleep(Duration::from_micros(delay)).await;
                        }
                    }
                    total_sent
                });

                let start = Instant::now();
                let mut total_chunks = 0u64;
                let mut total_redundant = 0u64;

                // 세그먼트 병렬 처리
                let _chunk_size = config.chunk_size;
                let segment_size = config.segment_size;
                let redundancy_ratio = config.base_redundancy_ratio;
                
                for segment_id in 1..=total_segments as u64 {
                    let offset = (segment_id as usize - 1) * segment_size;
                    let end = (offset + segment_size).min(data.len());
                    let segment_data = &data[offset..end];

                    // 세그먼트마다 암호화 (옵션)
                    let processed_data = if let Some(ref session) = crypto_session {
                        let mut session = session.lock().await;
                        session.encrypt(segment_id, segment_data)?
                    } else {
                        segment_data.to_vec()
                    };

                    // 청크 분할
                    let chunks = segment_builder.split_into_chunks(segment_id, &processed_data, 0);
                    let redundant_chunks = segment_builder.create_redundant_chunks(&chunks, redundancy_ratio);

                    // 재전송용으로 저장
                    {
                        let mut cache = segment_chunks.write().await;
                        cache.insert(segment_id, chunks.clone());
                    }

                    // 원본 청크 전송
                    for chunk in &chunks {
                        let bytes = chunk.to_bytes();
                        tx.send(bytes).await?;
                        total_chunks += 1;
                    }

                    // 중복 청크 전송
                    for chunk in &redundant_chunks {
                        let bytes = chunk.to_bytes();
                        tx.send(bytes).await?;
                        total_redundant += 1;
                    }
                    
                    // 세그먼트 전송 완료 카운터 증가
                    segments_sent.fetch_add(1, std::sync::atomic::Ordering::Relaxed);

                    // 진행률 표시 (100개마다)
                    if segment_id % 100 == 0 || segment_id == total_segments as u64 {
                        let progress = (segment_id as f64 / total_segments as f64) * 100.0;
                        let elapsed = start.elapsed().as_secs_f64();
                        let speed = end as f64 / elapsed / 1024.0 / 1024.0;
                        info!(
                            "📊 진행: {:.1}% | 세그먼트 {}/{} | {:.2} MB/s",
                            progress, segment_id, total_segments, speed
                        );
                    }
                }

                // 전송 완료 대기
                drop(tx);
                let _total_sent = send_task.await?;

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

                // 초기 전송 완료 - 이제 flow control 활성화
                initial_send_done.store(true, std::sync::atomic::Ordering::Relaxed);
                // NACK용 초기 지연 설정
                send_delay_us.store(100, std::sync::atomic::Ordering::Relaxed);

                // NACK 처리 및 재전송 (데이터 크기에 비례하여 대기)
                // 예상 전송 시간: 데이터크기 / 예상속도(5MB/s) + 여유시간
                let nack_wait_secs = ((data.len() as u64 / (5 * 1024 * 1024)) + 60).max(120);
                info!("⏳ NACK 대기 및 재전송 중 (최대 {}초)...", nack_wait_secs);
                let nack_start = Instant::now();
                let mut retransmit_count = 0u64;
                let mut last_nack_time = Instant::now();
                let mut completed_segments: std::collections::HashSet<u64> = std::collections::HashSet::new();

                while nack_start.elapsed() < Duration::from_secs(nack_wait_secs) {
                    // 30초간 NACK 없으면 종료 (전송 완료로 간주)
                    if last_nack_time.elapsed() > Duration::from_secs(30) && retransmit_count > 0 {
                        info!("⏱️  30초간 NACK 없음, 전송 완료로 간주");
                        break;
                    }

                    // 모든 세그먼트 완료 확인
                    if completed_segments.len() >= total_segments {
                        info!("✅ 모든 세그먼트 완료 확인!");
                        break;
                    }

                    match tokio::time::timeout(Duration::from_millis(50), socket.recv_from(&mut buf)).await {
                        Ok(Ok((len, _addr))) => {
                            // FlowControl 메시지 처리 (NACK 재전송 중 - 고정 딜레이 사용)
                            if let Some(_fc) = FlowControlMessage::from_bytes(&buf[..len]) {
                                // NACK 모드에서는 안정적인 고정 딜레이 사용
                                // (누적 손실률이 왜곡되어 있으므로)
                                let current_delay = send_delay_us.load(std::sync::atomic::Ordering::Relaxed);
                                // 천천히 속도 증가 (매 FC마다 5% 빨라짐, 최소 50us)
                                let new_delay = ((current_delay as f64 * 0.95) as u64).max(50);
                                send_delay_us.store(new_delay, std::sync::atomic::Ordering::Relaxed);
                            }
                            
                            // NACK 처리
                            if let Some(nack) = NackMessage::from_bytes(&buf[..len]) {
                                last_nack_time = Instant::now();
                                
                                // 재전송
                                let cache = segment_chunks.read().await;
                                if let Some(chunks) = cache.get(&nack.segment_id) {
                                    for &chunk_id in &nack.missing_chunk_ids {
                                        if let Some(chunk) = chunks.get(chunk_id as usize) {
                                            let bytes = chunk.to_bytes();
                                            socket.send_to(&bytes, client_addr).await?;
                                            retransmit_count += 1;
                                        }
                                    }
                                }

                                if retransmit_count % 1000 == 0 && retransmit_count > 0 {
                                    info!("📨 재전송 진행: {} 청크", retransmit_count);
                                }
                            }

                            // SegmentComplete 처리
                            if let Ok(header) = bincode::deserialize::<MessageHeader>(&buf[..len.min(32)]) {
                                if header.msg_type == MessageType::SegmentComplete {
                                    if len > 20 {
                                        if let Ok(seg_id) = bincode::deserialize::<u64>(&buf[16..24]) {
                                            completed_segments.insert(seg_id);
                                        }
                                    }
                                }
                            }
                        }
                        Err(_) => {}
                        _ => {}
                    }
                }

                info!("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");
                info!("🏁 서버 종료");
                info!("   총 재전송: {} 청크", retransmit_count);
                info!("   완료 세그먼트: {}/{}", completed_segments.len(), total_segments);
                info!("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");
                break;
            }
        }
    }

    Ok(())
}

/// 클라이언트 (수신자) 실행 - 병렬 처리 + 암호화 지원
async fn run_client(
    server_addr: SocketAddr,
    expected_size: usize,
    config: Config,
    encrypt: bool,
    num_workers: usize,
) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    info!("📡 클라이언트 시작");
    info!("🎯 서버: {}", server_addr);
    info!("📦 예상 크기: {} bytes ({:.2} MB)", expected_size, expected_size as f64 / 1024.0 / 1024.0);
    info!("⚙️  암호화: {}", if encrypt { "✅ 활성화" } else { "❌ 비활성화" });
    info!("⚙️  병렬 워커: {}", num_workers);

    // 소켓 생성
    let socket = Arc::new(UdpSocket::bind("0.0.0.0:0").await?);
    let mut buf = vec![0u8; 65535];

    // Init 메시지 전송
    let init_msg = sls::message::InitMessage::new(1);
    socket.send_to(&init_msg.to_bytes(), server_addr).await?;

    // 암호화 모드: 키 교환 먼저
    let crypto_session: Option<Arc<Mutex<CryptoSession>>> = if encrypt {
        info!("🔐 키 교환 시작...");
        
        // 클라이언트 키쌍 생성
        let client_keypair = EphemeralKeyPair::generate();
        let client_public = client_keypair.public_key_bytes();
        
        // 서버 공개키 수신 대기 (5초 타임아웃)
        let recv_result = tokio::time::timeout(
            Duration::from_secs(5),
            socket.recv_from(&mut buf)
        ).await;
        
        let (len, _) = match recv_result {
            Ok(Ok(r)) => r,
            Ok(Err(e)) => return Err(format!("서버 연결 오류: {}", e).into()),
            Err(_) => return Err("서버 응답 타임아웃 (5초) - 서버가 실행 중인지, 방화벽이 열려있는지 확인하세요".into()),
        };
        
        let server_key_msg = KeyExchangeMessage::from_bytes(&buf[..len])
            .ok_or("서버 공개키 수신 실패")?;
        info!("🔑 서버 공개키 수신 완료");
        
        // 클라이언트 공개키 전송
        let key_msg = KeyExchangeMessage { public_key: client_public };
        socket.send_to(&key_msg.to_bytes(), server_addr).await?;
        info!("🔑 클라이언트 공개키 전송 완료");
        
        // 세션 생성
        let session = CryptoSession::establish(client_keypair, server_key_msg.public_key);
        info!("🔐 키 교환 완료!");
        
        Some(Arc::new(Mutex::new(session)))
    } else {
        None
    };

    // InitAck 수신
    let (len, _) = socket.recv_from(&mut buf).await?;
    
    // InitAck 파싱 시도
    if let Some(_init_ack) = sls::message::InitAckMessage::from_bytes(&buf[..len]) {
        info!("✅ InitAck 수신 완료");
    } else {
        // InitAck이 아니면 이미 청크가 도착한 것일 수 있음
        info!("⚠️  InitAck 대신 다른 데이터 수신 ({}바이트) - 데이터 전송 시작된 것으로 간주", len);
    }
    
    info!("✅ 서버 연결 완료, 데이터 수신 대기...");

    let start = Instant::now();
    let expected_segments = (expected_size + config.segment_size - 1) / config.segment_size;
    
    // 세그먼트별 청크 저장
    let mut segment_chunks: HashMap<u64, HashMap<u32, Vec<u8>>> = HashMap::new();
    let mut segment_total_chunks: HashMap<u64, u32> = HashMap::new();
    let mut total_chunks_received = 0u64;
    let mut nack_count = 0u64;
    let mut last_progress_time = Instant::now();
    let mut last_chunk_time = Instant::now();
    let mut idle_nack_rounds = 0u32;
    
    // 복호화 채널 및 결과 저장소
    let (decrypt_tx, mut decrypt_rx) = mpsc::channel::<(u64, Vec<u8>)>(100);
    let decrypted_segments: Arc<Mutex<HashMap<u64, Vec<u8>>>> = Arc::new(Mutex::new(HashMap::new()));
    let decrypted_clone = decrypted_segments.clone();
    
    // 복호화 태스크 (암호화 모드시)
    let decrypt_task = if encrypt {
        let crypto = crypto_session.clone();
        Some(tokio::spawn(async move {
            while let Some((segment_id, encrypted_data)) = decrypt_rx.recv().await {
                let decrypted = if let Some(ref session) = crypto {
                    let session = session.lock().await;
                    session.decrypt(&encrypted_data).unwrap_or(encrypted_data)
                } else {
                    encrypted_data
                };
                decrypted_clone.lock().await.insert(segment_id, decrypted);
            }
        }))
    } else {
        None
    };
    
    // 완료된 세그먼트 추적 (암호화 전 상태)
    let mut assembled_segments: std::collections::HashSet<u64> = std::collections::HashSet::new();
    
    // 흐름 제어 통계
    let mut flow_control_time = Instant::now();
    let mut prev_chunks_received = 0u64;
    
    // 청크 수신 루프
    loop {
        // 짧은 타임아웃으로 빠른 NACK 대응
        match tokio::time::timeout(Duration::from_millis(100), socket.recv_from(&mut buf)).await {
            Ok(Ok((len, _))) => {
                last_chunk_time = Instant::now();
                idle_nack_rounds = 0;
                
                // 청크 파싱
                if let Some(chunk) = sls::chunk::Chunk::from_bytes(&buf[..len]) {
                    let segment_id = chunk.header.segment_id;
                    let chunk_id = chunk.header.chunk_id;
                    let total_chunks = chunk.header.total_chunks;
                    
                    // 총 청크 수 저장
                    segment_total_chunks.insert(segment_id, total_chunks);
                    
                    // 청크 저장
                    let segment = segment_chunks.entry(segment_id).or_insert_with(HashMap::new);
                    if !segment.contains_key(&chunk_id) {
                        segment.insert(chunk_id, chunk.data.to_vec());
                        total_chunks_received += 1;
                    }
                    
                    // 세그먼트 완료 체크 - 복호화 채널로 전송
                    if segment.len() >= total_chunks as usize && !assembled_segments.contains(&segment_id) {
                        // 청크 순서대로 조립
                        let mut segment_data = Vec::new();
                        for i in 0..total_chunks {
                            if let Some(chunk_data) = segment.get(&i) {
                                segment_data.extend_from_slice(chunk_data);
                            }
                        }
                        
                        assembled_segments.insert(segment_id);
                        
                        // 암호화 모드: 복호화 채널로 전송 (논블로킹)
                        if encrypt {
                            let _ = decrypt_tx.try_send((segment_id, segment_data));
                        } else {
                            // 비암호화: 직접 저장
                            decrypted_segments.lock().await.insert(segment_id, segment_data);
                        }
                    }
                    
                    // 진행률 표시 (0.5초마다)
                    if last_progress_time.elapsed() > Duration::from_millis(500) {
                        let progress = (assembled_segments.len() as f64 / expected_segments as f64) * 100.0;
                        let elapsed = start.elapsed().as_secs_f64();
                        let total_bytes = assembled_segments.len() * config.segment_size;
                        let speed = total_bytes as f64 / elapsed / 1024.0 / 1024.0;
                        info!(
                            "📊 수신: {:.1}% | 세그먼트 {}/{} | {:.2} MB | {:.2} MB/s",
                            progress.min(100.0), assembled_segments.len(), expected_segments, 
                            total_bytes as f64 / 1024.0 / 1024.0, speed
                        );
                        last_progress_time = Instant::now();
                    }
                    
                    // 흐름 제어 메시지 전송 (100ms마다, 데이터 수신 중에도!)
                    if flow_control_time.elapsed() > Duration::from_millis(100) {
                        let incomplete_segments = segment_chunks.len() - assembled_segments.len();
                        
                        // 클라이언트는 완료된 세그먼트 수 전송, 손실률은 서버에서 계산
                        let fc = FlowControlMessage::new(
                            assembled_segments.len() as u32,  // buffer_available → 완료 세그먼트 수
                            assembled_segments.iter().max().copied().unwrap_or(0),
                            incomplete_segments as u32,
                            0.0,  // 손실률은 서버에서 계산
                            assembled_segments.len() as f32,  // processing_rate → 완료 세그먼트 수
                        );
                        let _ = socket.send_to(&fc.to_bytes(), server_addr).await;
                        
                        prev_chunks_received = total_chunks_received;
                        flow_control_time = Instant::now();
                    }
                    
                    // 완료 체크
                    if assembled_segments.len() >= expected_segments {
                        info!("📦 모든 세그먼트 수신 완료");
                        break;
                    }
                }
            }
            Ok(Err(e)) => {
                warn!("수신 오류: {}", e);
                break;
            }
            Err(_) => {
                // 100ms 타임아웃 - NACK 전송
                idle_nack_rounds += 1;
                
                // 미완료 세그먼트에 NACK 전송
                let mut nacks_sent = 0;
                for (segment_id, chunks) in &segment_chunks {
                    if !assembled_segments.contains(segment_id) {
                        let total_chunks = segment_total_chunks.get(segment_id).copied().unwrap_or(55);
                        let received: std::collections::HashSet<u32> = chunks.keys().copied().collect();
                        let missing: Vec<u32> = (0..total_chunks)
                            .filter(|i| !received.contains(i))
                            .collect();
                        
                        if !missing.is_empty() {
                            let nack = NackMessage::new(*segment_id, missing.clone(), 0.0, 0);
                            let _ = socket.send_to(&nack.to_bytes(), server_addr).await;
                            nack_count += 1;
                            nacks_sent += 1;
                            
                            // 한 번에 너무 많은 NACK 전송 방지
                            if nacks_sent >= 50 {
                                break;
                            }
                        }
                    }
                }
                
                // 진행 상황 출력 (NACK 전송 시)
                if nacks_sent > 0 && idle_nack_rounds % 10 == 0 {
                    info!("📨 NACK 전송: {} 세그먼트 요청 (총 {}회)", nacks_sent, nack_count);
                }
                
                // 흐름 제어 메시지 전송 (100ms마다)
                if flow_control_time.elapsed() > Duration::from_millis(100) {
                    let incomplete_segments = segment_chunks.len() - assembled_segments.len();
                    
                    // 완료된 세그먼트 수 전송, 손실률은 서버에서 계산
                    let fc = FlowControlMessage::new(
                        assembled_segments.len() as u32,
                        assembled_segments.iter().max().copied().unwrap_or(0),
                        incomplete_segments as u32,
                        0.0,
                        assembled_segments.len() as f32,
                    );
                    let _ = socket.send_to(&fc.to_bytes(), server_addr).await;
                    
                    prev_chunks_received = total_chunks_received;
                    flow_control_time = Instant::now();
                }
                
                // 10초간 새 데이터 없고 95% 이상 받았으면 종료
                if last_chunk_time.elapsed() > Duration::from_secs(10) {
                    let progress = assembled_segments.len() as f64 / expected_segments as f64;
                    if progress >= 0.95 {
                        info!("✅ 95% 이상 수신 완료, 종료");
                        break;
                    }
                }
                
                // 60초간 새 데이터 없으면 종료
                if last_chunk_time.elapsed() > Duration::from_secs(60) {
                    info!("⏱️  60초간 새 데이터 없음, 종료");
                    break;
                }
                
                // 전체 타임아웃: 예상크기 / 예상속도(3MB/s) + 여유시간
                let total_timeout_secs = ((expected_size as u64 / (3 * 1024 * 1024)) + 120).max(180);
                if start.elapsed() > Duration::from_secs(total_timeout_secs) {
                    info!("⏱️  전체 타임아웃 ({}초)", total_timeout_secs);
                    break;
                }
            }
        }
    }

    // 복호화 태스크 종료 대기
    drop(decrypt_tx);
    if let Some(task) = decrypt_task {
        let _ = task.await;
    }

    // 세그먼트 순서대로 조립
    let final_segments = decrypted_segments.lock().await;
    let mut received_data = Vec::with_capacity(expected_size);
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
    let success_rate = if expected_size > 0 {
        (received_data.len() as f64 / expected_size as f64 * 100.0).min(100.0)
    } else {
        0.0
    };

    info!("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");
    info!("✅ 수신 완료!");
    info!("   시간: {:.2}s", elapsed.as_secs_f64());
    info!("   세그먼트: {}/{}", final_segments.len(), expected_segments);
    info!("   청크: {}", total_chunks_received);
    info!("   수신 크기: {:.2} MB / {:.2} MB", 
        received_data.len() as f64 / 1024.0 / 1024.0,
        expected_size as f64 / 1024.0 / 1024.0);
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

        let received = run_client(addr, data_size, config, encrypt, num_workers).await?;

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
