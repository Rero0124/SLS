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

use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;

use tracing::{info, Level};
use tracing_subscriber::FmtSubscriber;

use sls::multipath::PathManager;
use sls::receiver::Receiver;
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

    // PathManager 생성
    let path_manager = Arc::new(PathManager::new(client_config.config.clone()));

    // 수신자 시작
    let (receiver, mut segment_rx) = Receiver::start(
        client_config.config.clone(),
        client_config.bind_addr,
        client_config.server_addr,
        path_manager,
    )
    .await?;

    info!("Connected to server, waiting for data...");

    let start = std::time::Instant::now();
    let mut received_data = Vec::new();
    let mut segment_count = 0u64;

    // 데이터 수신
    loop {
        tokio::select! {
            segment = segment_rx.recv() => {
                match segment {
                    Some((segment_id, data)) => {
                        segment_count += 1;
                        info!(
                            "Received segment {}: {} bytes (total: {} bytes)",
                            segment_id,
                            data.len(),
                            received_data.len() + data.len()
                        );

                        received_data.extend_from_slice(&data);

                        // 예상 크기에 도달하면 종료
                        if let Some(expected) = client_config.expected_size {
                            if received_data.len() >= expected {
                                info!("Expected size reached, stopping...");
                                break;
                            }
                        }
                    }
                    None => {
                        info!("Channel closed");
                        break;
                    }
                }
            }
            _ = tokio::time::sleep(std::time::Duration::from_secs(10)) => {
                // 10초 타임아웃
                if segment_count > 0 {
                    info!("No more data received, assuming transfer complete");
                    break;
                }
            }
        }
    }

    let elapsed = start.elapsed();
    let stats = receiver.get_stats().await;

    info!("Transfer complete!");
    info!("  Time: {:.2}s", elapsed.as_secs_f64());
    info!("  Segments received: {}", segment_count);
    info!("  Total bytes: {}", received_data.len());
    info!(
        "  Throughput: {:.2} MB/s",
        received_data.len() as f64 / elapsed.as_secs_f64() / 1_000_000.0
    );
    info!("  NACKs sent: {}", stats.total_nacks);
    info!("  Loss rate: {:.2}%", stats.overall_loss_rate() * 100.0);

    // 파일 저장
    if let Some(output_path) = &client_config.output_path {
        std::fs::write(output_path, &received_data)?;
        info!("Data saved to {:?}", output_path);
    }

    // 수신자 정지
    receiver.stop().await;

    Ok(())
}
