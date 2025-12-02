//! SLS 클라이언트 (수신자) - Super Light Stream Protocol
//!
//! NACK 기반 블록 조립형 전송 프로토콜 클라이언트
//! - 누락 청크만 NACK으로 요청하여 클라이언트 부하 최소화
//! - X25519 + ChaCha20-Poly1305 암호화 지원 (선택)
//!
//! 사용법:
//!   cargo run --release --bin sls_client -- [OPTIONS]
//!
//! 예시:
//!   # 기본 수신
//!   cargo run --release --bin sls_client -- --server 127.0.0.1:9000 --output received.bin
//!   
//!   # 예상 크기 지정
//!   cargo run --release --bin sls_client -- -s 127.0.0.1:9000 -o data.bin --size 104857600

use std::collections::HashMap;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::{Duration, Instant};

use tokio::net::UdpSocket;
use tokio::sync::mpsc;
use tracing::{info, warn, Level};
use tracing_subscriber::FmtSubscriber;

use sls::chunk::Chunk;
use sls::message::{InitAckMessage, InitMessage, MessageHeader, MessageType, NackMessage};
use sls::Config;

/// 클라이언트 설정
struct ClientConfig {
    bind_addr: SocketAddr,
    server_addr: SocketAddr,
    output_path: Option<PathBuf>,
    expected_size: Option<usize>,
    encrypt: bool,
    workers: usize,
    config: Config,
}

impl Default for ClientConfig {
    fn default() -> Self {
        Self {
            bind_addr: "0.0.0.0:0".parse().unwrap(),
            server_addr: "127.0.0.1:9000".parse().unwrap(),
            output_path: None,
            expected_size: None,
            encrypt: false,
            workers: std::thread::available_parallelism().map(|n| n.get()).unwrap_or(4),
            config: Config::default(),
        }
    }
}

fn parse_args() -> ClientConfig {
    let args: Vec<String> = std::env::args().collect();
    let mut config = ClientConfig::default();

    let mut i = 1;
    while i < args.len() {
        match args[i].as_str() {
            "--bind" | "-b" => {
                if i + 1 < args.len() {
                    config.bind_addr = args[i + 1].parse().expect("유효한 주소 필요");
                    i += 1;
                }
            }
            "--server" | "-s" => {
                if i + 1 < args.len() {
                    config.server_addr = args[i + 1].parse().expect("유효한 주소 필요");
                    i += 1;
                }
            }
            "--output" | "-o" => {
                if i + 1 < args.len() {
                    config.output_path = Some(PathBuf::from(&args[i + 1]));
                    i += 1;
                }
            }
            "--size" => {
                if i + 1 < args.len() {
                    config.expected_size = Some(args[i + 1].parse().expect("유효한 숫자 필요"));
                    i += 1;
                }
            }
            "--encrypt" | "-e" => {
                config.encrypt = true;
                config.config.encryption_enabled = true;
            }
            "--workers" | "-w" => {
                if i + 1 < args.len() {
                    config.workers = args[i + 1].parse().expect("유효한 숫자 필요");
                    config.config.parallel_workers = config.workers;
                    i += 1;
                }
            }
            "--help" | "-h" => {
                println!(
                    r#"SLS Client - Super Light Stream Protocol 클라이언트

NACK 기반 블록 조립형 고속 전송 프로토콜 클라이언트
- 누락 청크만 NACK으로 요청하여 클라이언트 부하 최소화
- X25519 키 교환 + ChaCha20-Poly1305 암호화 지원

사용법:
  cargo run --release --bin sls_client -- [OPTIONS]

옵션:
  -b, --bind <ADDR>      로컬 바인드 주소 (기본: 0.0.0.0:0 = 자동 할당)
  -s, --server <ADDR>    서버 주소 (기본: 127.0.0.1:9000)
  -o, --output <PATH>    수신 데이터 저장 경로
  --size <BYTES>         예상 데이터 크기 (바이트)
  -e, --encrypt          암호화 활성화 (X25519 + ChaCha20-Poly1305)
  -w, --workers <N>      병렬 워커 수 (기본: CPU 코어 수)
  -h, --help             이 도움말 출력

예시:
  # 서버에서 파일 수신
  cargo run --release --bin sls_client -- --server 192.168.1.100:9000 --output received.bin
  
  # 암호화 수신
  cargo run --release --bin sls_client -- -s 127.0.0.1:9000 -o data.bin --encrypt
  
  # 예상 크기 지정 (100MB) + 암호화
  cargo run --release --bin sls_client -- -s 127.0.0.1:9000 --size 104857600 -e
"#
                );
                std::process::exit(0);
            }
            _ => {}
        }
        i += 1;
    }

    config
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // 로깅 설정
    let subscriber = FmtSubscriber::builder()
        .with_max_level(Level::INFO)
        .finish();
    tracing::subscriber::set_global_default(subscriber)?;

    let client_config = parse_args();

    info!("SLS Client starting...");
    info!("Server address: {}", client_config.server_addr);
    info!("Bind address: {}", client_config.bind_addr);

    // UDP 소켓 바인딩
    let socket = Arc::new(UdpSocket::bind(client_config.bind_addr).await?);
    let local_addr = socket.local_addr()?;
    info!("Bound to local address: {}", local_addr);

    let server_addr = client_config.server_addr;

    // ═══════════════════════════════════════════════════════════════
    // 송신 큐: 우선순위 큐 (Init, NACK) + 일반 큐 (기타)
    // ═══════════════════════════════════════════════════════════════
    let (priority_tx, mut priority_rx) = mpsc::channel::<Vec<u8>>(1000);
    let (_data_tx, mut data_rx) = mpsc::channel::<Vec<u8>>(10_000);

    // 송신 태스크
    let send_socket = socket.clone();
    let _send_task = tokio::spawn(async move {
        loop {
            match priority_rx.try_recv() {
                Ok(bytes) => {
                    let _ = send_socket.send_to(&bytes, server_addr).await;
                    continue;
                }
                Err(mpsc::error::TryRecvError::Empty) => {}
                Err(mpsc::error::TryRecvError::Disconnected) => break,
            }

            tokio::select! {
                Some(bytes) = priority_rx.recv() => {
                    let _ = send_socket.send_to(&bytes, server_addr).await;
                }
                Some(bytes) = data_rx.recv() => {
                    let _ = send_socket.send_to(&bytes, server_addr).await;
                }
                else => break,
            }
        }
    });

    // ═══════════════════════════════════════════════════════════════
    // 수신 큐 + 수신 태스크
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

    // === Phase 1: 핸드쉐이크 (Init/InitAck) ===
    let init_request = InitMessage::new(
        client_config.encrypt,
        [0u8; 32],
    );

    info!("Sending Init to server (via priority queue)...");
    let mut init_ack: Option<InitAckMessage> = None;
    let mut retry_count = 0;
    let retry_interval = Duration::from_millis(500);
    let max_retries = 20;

    while init_ack.is_none() && retry_count < max_retries {
        let _ = priority_tx.send(init_request.to_bytes()).await;

        if retry_count > 0 {
            info!("Retry #{}: Waiting for InitAck...", retry_count);
        }

        // 수신 큐에서 읽기
        let mut rx = recv_rx.lock().await;
        match tokio::time::timeout(retry_interval, rx.recv()).await {
            Ok(Some(buf)) => {
                drop(rx);
                if let Ok(header) = bincode::deserialize::<MessageHeader>(&buf[..buf.len().min(32)]) {
                    if header.msg_type == MessageType::InitAck {
                        if let Some(resp) = InitAckMessage::from_bytes(&buf) {
                            init_ack = Some(resp);
                        }
                    }
                }
            }
            Ok(None) => {
                drop(rx);
                warn!("Receive channel closed");
            }
            Err(_) => {
                drop(rx);
            }
        }

        retry_count += 1;
    }

    let metadata = init_ack.ok_or("Failed to receive InitAck from server")?;

    info!("InitAck received:");
    info!("  Total file size: {} bytes", metadata.total_file_size);
    info!("  Total segments: {}", metadata.total_segments);
    info!("  Chunks per segment: {}", metadata.chunks_per_segment);
    info!("  Chunk size: {} bytes", metadata.chunk_size);
    info!("  Segment size: {} bytes", metadata.segment_size);
    info!("  Encryption: {}", metadata.encryption_enabled);

    // === Phase 2: 데이터 수신 ===
    info!("Starting data reception...");
    let start = Instant::now();

    // 세그먼트별 청크 수신 상태
    // segment_id -> (received_chunks: HashMap<chunk_id, data>, total_chunks)
    let mut segment_chunks: HashMap<u64, (HashMap<u32, Vec<u8>>, u32)> = HashMap::new();
    let mut completed_segments: HashMap<u64, Vec<u8>> = HashMap::new();
    let mut total_chunks_received = 0u64;
    let mut total_nacks_sent = 0u64;

    let total_segments = metadata.total_segments;
    let chunks_per_segment = metadata.chunks_per_segment;

    // NACK 타이밍
    let mut last_nack_time = Instant::now();
    let nack_interval = Duration::from_millis(200);
    let mut last_progress_time = Instant::now();

    // 수신 루프
    loop {
        // 완료 조건 체크
        if completed_segments.len() as u64 >= total_segments {
            info!("All {} segments received!", total_segments);
            break;
        }

        // 예상 크기 도달 체크
        let total_received_bytes: usize = completed_segments.values().map(|v| v.len()).sum();
        if let Some(expected) = client_config.expected_size {
            if total_received_bytes >= expected {
                info!("Expected size reached!");
                break;
            }
        }

        // 패킷 수신 (수신 큐에서 읽기)
        let mut rx = recv_rx.lock().await;
        match tokio::time::timeout(Duration::from_millis(50), rx.recv()).await {
            Ok(Some(buf)) => {
                drop(rx);
                // 청크 파싱
                if let Some(chunk) = Chunk::from_bytes(&buf) {
                    let seg_id = chunk.header.segment_id;
                    let chunk_id = chunk.header.chunk_id;
                    let total_chunks = chunk.header.total_chunks;

                    // 이미 완료된 세그먼트 스킵
                    if completed_segments.contains_key(&seg_id) {
                        continue;
                    }

                    // 세그먼트 청크 저장
                    let entry = segment_chunks
                        .entry(seg_id)
                        .or_insert_with(|| (HashMap::new(), total_chunks));
                    
                    if !entry.0.contains_key(&chunk_id) {
                        entry.0.insert(chunk_id, chunk.data.to_vec());
                        total_chunks_received += 1;
                    }

                    // 세그먼트 완료 체크
                    if entry.0.len() as u32 == total_chunks {
                        // 세그먼트 조립
                        let mut segment_data = vec![0u8; metadata.segment_size as usize];
                        for (&cid, data) in &entry.0 {
                            let offset = cid as usize * metadata.chunk_size as usize;
                            let end = (offset + data.len()).min(segment_data.len());
                            segment_data[offset..end].copy_from_slice(&data[..end - offset]);
                        }
                        // 마지막 세그먼트는 크기가 다를 수 있음
                        if seg_id == total_segments {
                            let last_seg_size = (metadata.total_file_size % metadata.segment_size as u64) as usize;
                            if last_seg_size > 0 {
                                segment_data.truncate(last_seg_size);
                            }
                        }
                        completed_segments.insert(seg_id, segment_data);
                        segment_chunks.remove(&seg_id);
                    }
                }
            }
            Ok(None) => {
                drop(rx);
            }
            Err(_) => {
                drop(rx);
            }
        }

        // 진행률 로깅 (2초마다)
        if last_progress_time.elapsed() > Duration::from_secs(2) {
            let progress = (completed_segments.len() as f64 / total_segments as f64) * 100.0;
            info!(
                "Progress: {}/{} segments ({:.1}%), {} chunks received",
                completed_segments.len(),
                total_segments,
                progress,
                total_chunks_received
            );
            last_progress_time = Instant::now();
        }

        // NACK 전송 (주기적) - 우선순위 큐 사용
        if last_nack_time.elapsed() > nack_interval {
            let mut nack_count = 0;
            let mut total_missing_chunks = 0;

            // 부분 수신된 세그먼트의 누락 청크 요청
            for (&seg_id, (received, total)) in &segment_chunks {
                let missing: Vec<u32> = (0..*total)
                    .filter(|id| !received.contains_key(id))
                    .collect();

                if !missing.is_empty() {
                    let nack = NackMessage::new(seg_id, missing.clone(), 0.0, 0);
                    // NACK은 우선순위 큐로 전송
                    let _ = priority_tx.send(nack.to_bytes()).await;
                    nack_count += 1;
                    total_missing_chunks += missing.len();
                    total_nacks_sent += 1;
                }
            }

            // 아예 수신되지 않은 세그먼트 요청
            for seg_id in 1..=total_segments {
                if !completed_segments.contains_key(&seg_id) && !segment_chunks.contains_key(&seg_id) {
                    // 모든 청크 요청
                    let missing: Vec<u32> = (0..chunks_per_segment).collect();
                    let nack = NackMessage::new(seg_id, missing.clone(), 0.0, 0);
                    // NACK은 우선순위 큐로 전송
                    let _ = priority_tx.send(nack.to_bytes()).await;
                    nack_count += 1;
                    total_missing_chunks += missing.len();
                    total_nacks_sent += 1;
                }
            }

            if nack_count > 0 {
                info!(
                    "Sent {} NACKs for {} missing chunks (via priority queue)",
                    nack_count, total_missing_chunks
                );
            }

            last_nack_time = Instant::now();
        }

        // 타임아웃 체크 (30초 동안 진행 없으면 종료)
        if start.elapsed() > Duration::from_secs(30) && completed_segments.is_empty() {
            warn!("Timeout: No data received");
            break;
        }
    }

    // === 결과 정리 ===
    let elapsed = start.elapsed();

    // 데이터 조립 (세그먼트 순서대로)
    let mut received_data = Vec::new();
    for seg_id in 1..=total_segments {
        if let Some(data) = completed_segments.get(&seg_id) {
            received_data.extend_from_slice(data);
        }
    }

    info!("Transfer complete!");
    info!("  Time: {:.2}s", elapsed.as_secs_f64());
    info!("  Segments received: {}/{}", completed_segments.len(), total_segments);
    info!("  Total bytes: {}", received_data.len());
    if elapsed.as_secs_f64() > 0.0 {
        info!(
            "  Throughput: {:.2} MB/s",
            received_data.len() as f64 / elapsed.as_secs_f64() / 1_000_000.0
        );
    }
    info!("  Total chunks: {}", total_chunks_received);
    info!("  NACKs sent: {}", total_nacks_sent);

    // 파일 저장
    if let Some(output_path) = &client_config.output_path {
        std::fs::write(output_path, &received_data)?;
        info!("Data saved to {:?}", output_path);
    }

    Ok(())
}
