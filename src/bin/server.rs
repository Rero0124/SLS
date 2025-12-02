//! SLS 서버 (송신자) - Super Light Stream Protocol
//!
//! NACK 기반 블록 조립형 전송 프로토콜 서버
//! - 공격적 전송 + NACK 재전송으로 고속 전송
//! - X25519 + ChaCha20-Poly1305 암호화 지원 (선택)
//!
//! 사용법:
//!   cargo run --release --bin sls_server -- [OPTIONS]
//!
//! 예시:
//!   # 기본 전송
//!   cargo run --release --bin sls_server -- --bind 0.0.0.0:9000 --file data.bin
//!   
//!   # 암호화 전송 + 50% 중복
//!   cargo run --release --bin sls_server -- -f data.bin --encrypt --redundancy 0.5

use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;

use tokio::net::UdpSocket;
use tokio::sync::mpsc;
use tracing::{info, Level};
use tracing_subscriber::FmtSubscriber;

use sls::chunk::SegmentBuilder;
use sls::message::{InitAckMessage, InitMessage, MessageHeader, MessageType, NackMessage};
use sls::Config;

/// 서버 설정
struct ServerConfig {
    bind_addr: SocketAddr,
    file_path: Option<PathBuf>,
    encrypt: bool,
    workers: usize,
    config: Config,
}

impl Default for ServerConfig {
    fn default() -> Self {
        Self {
            bind_addr: "0.0.0.0:9000".parse().unwrap(),
            file_path: None,
            encrypt: false,
            workers: std::thread::available_parallelism().map(|n| n.get()).unwrap_or(4),
            config: Config::default(),
        }
    }
}

fn parse_args() -> ServerConfig {
    let args: Vec<String> = std::env::args().collect();
    let mut config = ServerConfig::default();

    let mut i = 1;
    while i < args.len() {
        match args[i].as_str() {
            "--bind" | "-b" => {
                if i + 1 < args.len() {
                    config.bind_addr = args[i + 1].parse().expect("유효한 주소 필요");
                    i += 1;
                }
            }
            "--file" | "-f" => {
                if i + 1 < args.len() {
                    config.file_path = Some(PathBuf::from(&args[i + 1]));
                    i += 1;
                }
            }
            "--chunk-size" => {
                if i + 1 < args.len() {
                    config.config.chunk_size = args[i + 1].parse().expect("유효한 숫자 필요");
                    i += 1;
                }
            }
            "--segment-size" => {
                if i + 1 < args.len() {
                    config.config.segment_size = args[i + 1].parse().expect("유효한 숫자 필요");
                    i += 1;
                }
            }
            "--redundancy" => {
                if i + 1 < args.len() {
                    config.config.base_redundancy_ratio =
                        args[i + 1].parse().expect("유효한 숫자 필요");
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
                    r#"SLS Server - Super Light Stream Protocol 서버

NACK 기반 블록 조립형 고속 전송 프로토콜 서버
- 공격적 전송 + NACK 기반 재전송
- X25519 키 교환 + ChaCha20-Poly1305 암호화 지원

사용법:
  cargo run --release --bin sls_server -- [OPTIONS]

옵션:
  -b, --bind <ADDR>       바인드 주소 (기본: 0.0.0.0:9000)
  -f, --file <PATH>       전송할 파일 경로
  -e, --encrypt           암호화 활성화 (X25519 + ChaCha20-Poly1305)
  -w, --workers <N>       병렬 워커 수 (기본: CPU 코어 수)
  --chunk-size <SIZE>     청크 크기 바이트 (기본: 1200)
  --segment-size <SIZE>   세그먼트 크기 바이트 (기본: 65536)
  --redundancy <RATIO>    중복 전송 비율 0.0~1.0 (기본: 0.15 = 15%)
  -h, --help              이 도움말 출력

예시:
  # 파일 전송
  cargo run --release --bin sls_server -- --file large_file.bin
  
  # 암호화 전송
  cargo run --release --bin sls_server -- -f data.bin --encrypt
  
  # 30% 중복 + 암호화 (불안정 네트워크용)
  cargo run --release --bin sls_server -- -f data.bin --redundancy 0.3 -e
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

    let server_config = parse_args();

    info!("SLS Server starting...");
    info!("Bind address: {}", server_config.bind_addr);
    info!("Chunk size: {} bytes", server_config.config.chunk_size);
    info!("Segment size: {} bytes", server_config.config.segment_size);
    info!(
        "Base redundancy: {:.1}%",
        server_config.config.base_redundancy_ratio * 100.0
    );

    // 전송할 데이터 준비
    let data = if let Some(path) = &server_config.file_path {
        info!("Loading file: {:?}", path);
        std::fs::read(path)?
    } else {
        // 테스트용 더미 데이터 (1MB)
        info!("Using test data (1MB)");
        vec![0xABu8; 1024 * 1024]
    };

    info!("Data size: {} bytes", data.len());

    // 소켓 바인딩
    let socket = Arc::new(UdpSocket::bind(server_config.bind_addr).await?);
    info!("Server listening on {}", server_config.bind_addr);

    // 세그먼트 빌더
    let segment_builder = Arc::new(SegmentBuilder::new(server_config.config.chunk_size));
    let config = server_config.config.clone();

    // 세그먼트 데이터 캐시 (NACK 재전송용)
    let segment_cache: Arc<tokio::sync::RwLock<std::collections::HashMap<u64, Vec<u8>>>> =
        Arc::new(tokio::sync::RwLock::new(std::collections::HashMap::new()));

    // ═══════════════════════════════════════════════════════════════
    // 송신 큐: 우선순위 큐 + 일반 데이터 큐
    // ═══════════════════════════════════════════════════════════════
    let (priority_tx, mut priority_rx) = mpsc::channel::<(Vec<u8>, SocketAddr)>(1000);
    let (data_tx, mut data_rx) = mpsc::channel::<(Vec<u8>, SocketAddr)>(100_000);

    // ─────────────────────────────────────────────────────────────────
    // 송신 태스크: 우선순위 큐 먼저, 그 다음 일반 큐
    // ─────────────────────────────────────────────────────────────────
    let send_socket = socket.clone();
    let _send_task = tokio::spawn(async move {
        loop {
            // 1. 우선순위 큐 확인 (non-blocking)
            match priority_rx.try_recv() {
                Ok((bytes, addr)) => {
                    let _ = send_socket.send_to(&bytes, addr).await;
                    continue; // 우선순위 큐에 더 있을 수 있으므로 다시 확인
                }
                Err(mpsc::error::TryRecvError::Empty) => {}
                Err(mpsc::error::TryRecvError::Disconnected) => break,
            }

            // 2. 일반 큐 확인 (짧은 타임아웃)
            tokio::select! {
                Some((bytes, addr)) = priority_rx.recv() => {
                    let _ = send_socket.send_to(&bytes, addr).await;
                }
                Some((bytes, addr)) = data_rx.recv() => {
                    let _ = send_socket.send_to(&bytes, addr).await;
                }
                else => break,
            }
        }
    });

    // ─────────────────────────────────────────────────────────────────
    // 수신 및 처리 루프
    // ─────────────────────────────────────────────────────────────────
    let mut buf = vec![0u8; 65535];
    let data = Arc::new(data);

    info!("Waiting for client connection (Init)...");

    loop {
        let (len, addr) = socket.recv_from(&mut buf).await?;

        // 메시지 파싱
        if let Ok(header) = bincode::deserialize::<MessageHeader>(&buf[..len.min(32)]) {
            match header.msg_type {
                MessageType::Init => {
                    // 초기화 요청 처리
                    if let Some(init_req) = InitMessage::from_bytes(&buf[..len]) {
                        info!("Init received from: {}", addr);
                        info!("  Client encryption: {}", init_req.encryption_enabled);
                        info!("  Protocol version: {}", init_req.protocol_version);

                        // InitAck 응답 생성
                        let mut init_ack = InitAckMessage::new(
                            data.len() as u64,
                            config.chunk_size as u16,
                            config.segment_size as u32,
                            config.base_redundancy_ratio as f32,
                        );
                        init_ack.encryption_enabled = init_req.encryption_enabled;

                        // InitAck을 우선순위 큐로 전송
                        let _ = priority_tx.send((init_ack.to_bytes(), addr)).await;
                        
                        info!("InitAck queued (priority):");
                        info!("  Total file size: {} bytes", init_ack.total_file_size);
                        info!("  Total segments: {}", init_ack.total_segments);

                        // 데이터 전송 시작 (별도 태스크로)
                        let data_clone = data.clone();
                        let config_clone = config.clone();
                        let segment_builder_clone = segment_builder.clone();
                        let segment_cache_clone = segment_cache.clone();
                        let data_tx_clone = data_tx.clone();
                        
                        tokio::spawn(async move {
                            info!("Starting data transfer...");
                            let start = std::time::Instant::now();

                            let mut segment_id = 1u64;
                            let mut offset = 0;
                            let mut total_chunks = 0u64;
                            let total_segments = init_ack.total_segments;

                            while offset < data_clone.len() {
                                let end = (offset + config_clone.segment_size).min(data_clone.len());
                                let segment_data = &data_clone[offset..end];

                                // 세그먼트 캐시 저장
                                {
                                    let mut cache = segment_cache_clone.write().await;
                                    cache.insert(segment_id, segment_data.to_vec());
                                }

                                // 청크 분할 및 전송
                                let chunks = segment_builder_clone.split_into_chunks(segment_id, segment_data, 0);
                                let redundant_chunks = segment_builder_clone
                                    .create_redundant_chunks(&chunks, config_clone.base_redundancy_ratio);

                                for chunk in chunks.iter().chain(redundant_chunks.iter()) {
                                    let bytes = chunk.to_bytes();
                                    // 일반 데이터 큐로 전송
                                    if data_tx_clone.send((bytes, addr)).await.is_err() {
                                        return;
                                    }
                                    total_chunks += 1;
                                }

                                if segment_id % 10 == 0 || offset + config_clone.segment_size >= data_clone.len() {
                                    info!(
                                        "Progress: segment {}/{} ({:.1}%)",
                                        segment_id, total_segments,
                                        (offset as f64 / data_clone.len() as f64) * 100.0
                                    );
                                }

                                segment_id += 1;
                                offset = end;
                            }

                            let elapsed = start.elapsed();
                            let throughput = data_clone.len() as f64 / elapsed.as_secs_f64() / 1_000_000.0;

                            info!("Initial transfer complete!");
                            info!("  Time: {:.2}s", elapsed.as_secs_f64());
                            info!("  Total chunks: {}", total_chunks);
                            info!("  Throughput: {:.2} MB/s", throughput);
                            info!("Waiting for NACK retransmission requests...");
                        });
                    }
                }

                MessageType::Nack => {
                    // NACK 처리 - 재전송
                    if let Some(nack) = NackMessage::from_bytes(&buf[..len]) {
                        let segment_builder_clone = segment_builder.clone();
                        let segment_cache_clone = segment_cache.clone();
                        let data_tx_clone = data_tx.clone();
                        
                        // 재전송도 별도 태스크로 처리
                        tokio::spawn(async move {
                            let cache = segment_cache_clone.read().await;
                            if let Some(segment_data) = cache.get(&nack.segment_id) {
                                let chunks = segment_builder_clone.split_into_chunks(
                                    nack.segment_id,
                                    segment_data,
                                    0,
                                );

                                for &chunk_id in &nack.missing_chunk_ids {
                                    if let Some(chunk) = chunks.iter().find(|c| c.header.chunk_id == chunk_id) {
                                        let bytes = chunk.to_bytes();
                                        let _ = data_tx_clone.send((bytes, addr)).await;
                                    }
                                }
                            }
                        });
                    }
                }

                MessageType::SegmentComplete => {
                    // 세그먼트 완료 - 캐시에서 제거 가능
                }

                MessageType::Close => {
                    info!("Client disconnected: {}", addr);
                }

                _ => {}
            }
        }
    }

    #[allow(unreachable_code)]
    {
        let _ = _send_task.await;
        Ok(())
    }
}
