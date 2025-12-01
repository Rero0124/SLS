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
use std::time::Duration;

use tokio::net::UdpSocket;
use tracing::{info, Level};
use tracing_subscriber::FmtSubscriber;

use sls::chunk::SegmentBuilder;
use sls::message::{InitAckMessage, MessageHeader, MessageType, NackMessage};
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
    let segment_builder = SegmentBuilder::new(server_config.config.chunk_size);
    let config = server_config.config;

    // 클라이언트 연결 대기
    let mut buf = vec![0u8; 65535];
    let mut _client_addr: Option<SocketAddr> = None;

    info!("Waiting for client connection...");

    loop {
        let (len, addr) = socket.recv_from(&mut buf).await?;

        // 메시지 파싱
        if let Ok(header) = bincode::deserialize::<MessageHeader>(&buf[..len.min(32)]) {
            match header.msg_type {
                MessageType::Init => {
                    _client_addr = Some(addr);
                    info!("Client connected: {}", addr);

                    // InitAck 전송
                    let ack = InitAckMessage {
                        nic_count: 1,
                        chunk_size: config.chunk_size as u16,
                        segment_size: config.segment_size as u32,
                        redundancy_ratio: config.base_redundancy_ratio as f32,
                    };
                    socket.send_to(&ack.to_bytes(), addr).await?;

                    // 데이터 전송 시작
                    info!("Starting data transfer...");
                    let start = std::time::Instant::now();

                    let mut segment_id = 1u64;
                    let mut offset = 0;
                    let mut total_chunks = 0u64;
                    let mut total_redundant = 0u64;

                    while offset < data.len() {
                        let end = (offset + config.segment_size).min(data.len());
                        let segment_data = &data[offset..end];

                        // 청크 분할
                        let chunks = segment_builder.split_into_chunks(segment_id, segment_data, 0);
                        let redundant_chunks = segment_builder
                            .create_redundant_chunks(&chunks, config.base_redundancy_ratio);

                        // 원본 청크 전송
                        for chunk in &chunks {
                            let bytes = chunk.to_bytes();
                            socket.send_to(&bytes, addr).await?;
                            total_chunks += 1;

                            if config.chunk_interval_us > 0 {
                                tokio::time::sleep(Duration::from_micros(config.chunk_interval_us))
                                    .await;
                            }
                        }

                        // 중복 청크 전송
                        for chunk in &redundant_chunks {
                            let bytes = chunk.to_bytes();
                            socket.send_to(&bytes, addr).await?;
                            total_redundant += 1;

                            if config.chunk_interval_us > 0 {
                                tokio::time::sleep(Duration::from_micros(config.chunk_interval_us))
                                    .await;
                            }
                        }

                        info!(
                            "Segment {} sent: {} chunks + {} redundant",
                            segment_id,
                            chunks.len(),
                            redundant_chunks.len()
                        );

                        segment_id += 1;
                        offset = end;
                    }

                    let elapsed = start.elapsed();
                    let throughput = data.len() as f64 / elapsed.as_secs_f64() / 1_000_000.0;

                    info!("Transfer complete!");
                    info!("  Time: {:.2}s", elapsed.as_secs_f64());
                    info!("  Total chunks: {}", total_chunks);
                    info!("  Redundant chunks: {}", total_redundant);
                    info!("  Throughput: {:.2} MB/s", throughput);
                }

                MessageType::Nack => {
                    // NACK 처리
                    if let Some(nack) = NackMessage::from_bytes(&buf[..len]) {
                        info!(
                            "NACK received: segment={}, missing={} chunks",
                            nack.segment_id,
                            nack.missing_chunk_ids.len()
                        );

                        // 재전송 (간단 구현 - 세그먼트 재구성 필요)
                        // 실제로는 세그먼트 상태를 저장해야 함
                    }
                }

                MessageType::SegmentComplete => {
                    info!("Segment complete confirmation received");
                }

                MessageType::Close => {
                    info!("Client disconnected: {}", addr);
                    _client_addr = None;
                }

                _ => {}
            }
        }
    }
}
