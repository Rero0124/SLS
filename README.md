# SFP (Super Fast Protocol)

UDP 기반 **NACK 블록 조립형** 전송 프로토콜 - Rust 구현

## 🔥 핵심 철학

- **NACK 기반**: ACK 없음, 누락된 청크만 요청
- **블록/퍼즐 조립**: 스트림이 아닌 세그먼트 단위 전송
- **Forward Redundancy**: 중복 전송으로 손실 보정
- **저사양 최적화**: 클라이언트 부담 최소화
- **BBR-lite 혼잡제어**: RTT/대역폭 기반 동적 pacing
- **백프레셔**: 큐 기반 자동 흐름 제어

## ⚡ 성능

| 테스트 환경 | 처리량 | NACK 횟수 |
|------------|--------|-----------|
| 로컬 (2GB, 암호화) | **200+ MB/s** (서버) / 80 MB/s (수신) | ~1,200회 |
| 로컬 (2GB, 비암호화) | **210+ MB/s** | ~1,000회 |

## 📦 구조

```
SFP/
├── src/
│   ├── lib.rs           # 라이브러리 진입점
│   ├── bbr.rs           # BBR-lite 혼잡제어
│   ├── chunk.rs         # Segment/Chunk 정의
│   ├── config.rs        # 프로토콜 설정
│   ├── crypto.rs        # X25519 + ChaCha20-Poly1305 암호화
│   ├── error.rs         # 에러 타입
│   ├── message.rs       # 프로토콜 메시지 (NACK 등)
│   ├── multipath.rs     # 멀티패스 관리
│   ├── receiver.rs      # 수신자 (클라이언트)
│   ├── sender.rs        # 송신자 (서버)
│   ├── stats.rs         # 전송 통계
│   └── bin/
│       ├── server.rs    # 서버 실행 파일
│       └── client.rs    # 클라이언트 실행 파일
├── examples/
│   └── large_file_test.rs  # 대용량 파일 전송 테스트
└── Cargo.toml
```

## 🚀 빌드 및 실행

```bash
# 빌드
cargo build --release

# 서버 실행 (송신자)
cargo run --release --bin sfp-server -- --bind 0.0.0.0:9000 --file data.bin

# 클라이언트 실행 (수신자)
cargo run --release --bin sfp-client -- --server 127.0.0.1:9000 --output received.bin

# 대용량 파일 전송 테스트 (2GB, 암호화)
cargo run --release --example large_file_test -- --server --size 2000 --encrypt
cargo run --release --example large_file_test -- --client --encrypt
```

## 📊 프로토콜 개요

### 전송 단위

| 단위 | 크기 | 설명 |
|------|------|------|
| **Segment** | 64KB (기본) | 논리적 블록, 조립 단위 |
| **Chunk** | 1200 bytes (기본) | UDP 패킷 단위, 퍼즐 조각 |

### 메시지 타입

| 타입 | 방향 | 설명 |
|------|------|------|
| `Init` | Client → Server | 연결 초기화 (공개키, 설정 협상) |
| `InitAck` | Server → Client | 초기화 응답 (파일 크기, 세그먼트 수, 세션키) |
| `Chunk` | Server → Client | 데이터 청크 |
| `NACK` | Client → Server | 누락 청크 요청 |
| `SegmentComplete` | Client → Server | 세그먼트 조립 완료 |
| `FlowControl` | Client → Server | 흐름 제어 피드백 (버퍼, 손실률) |
| `Heartbeat` | 양방향 | 생존 확인 |
| `Close` | 양방향 | 연결 종료 |

### 연결 및 전송 흐름

```
서버 (송신자)                              클라이언트 (수신자)
     │                                          │
     │<─────────── Init ────────────────────────│  ① 연결 요청 (공개키, 설정)
     │                                          │
     │──────────── InitAck ────────────────────>│  ② 응답 (파일크기, 세그먼트수, 세션키)
     │                                          │
     │  ╔══════════════════════════════════════════════════════════╗
     │  ║              세그먼트 전송 루프 (segment 0..N)             ║
     │  ╚══════════════════════════════════════════════════════════╝
     │                                          │
     │──── Chunk[seg_id, chunk_0] ─────────────>│  ③ 청크 전송 시작
     │──── Chunk[seg_id, chunk_1] ─────────────>│
     │──── ...                                  │
     │──── Chunk[seg_id, chunk_N] ─────────────>│
     │──── Redundant Chunk (중복) ─────────────>│  ④ Forward Redundancy
     │                                          │
     │<─────────── NACK [missing: 3,7,12] ──────│  ⑤ 누락 청크 요청 (필요시만)
     │                                          │
     │──── Chunk[seg_id, chunk_3] ─────────────>│  ⑥ 캐시된 청크 재전송
     │──── Chunk[seg_id, chunk_7] ─────────────>│
     │──── Chunk[seg_id, chunk_12] ────────────>│
     │                                          │
     │<─────────── SegmentComplete ─────────────│  ⑦ 세그먼트 조립 완료
     │                                          │
     │<─────────── FlowControl ─────────────────│  ⑧ 흐름 제어 (주기적)
     │                                          │
     │  ╔══════════════════════════════════════════════════════════╗
     │  ║                    다음 세그먼트 반복                      ║
     │  ╚══════════════════════════════════════════════════════════╝
     │                                          │
     │<─────────── Close ───────────────────────│  ⑨ 전송 완료
```

### Init/InitAck 협상 내용

```rust
// Init (클라이언트 → 서버)
struct InitMessage {
    client_public_key: [u8; 32],  // X25519 공개키
    encryption_enabled: bool,
    nic_count: u8,
    chunk_size: u16,              // 0이면 서버 기본값
    segment_size: u32,
    buffer_size: u32,
    timestamp_us: u64,            // RTT 측정용
}

// InitAck (서버 → 클라이언트)
struct InitAckMessage {
    server_public_key: [u8; 32],
    session_key: [u8; 32],        // ECDH로 유도
    encryption_enabled: bool,
    chunk_size: u16,              // 확정된 값
    segment_size: u32,
    redundancy_ratio: f32,
    total_file_size: u64,         // 전송할 파일 크기
    total_segments: u64,          // 총 세그먼트 수
    chunks_per_segment: u32,
    client_timestamp_us: u64,     // 에코 (RTT 계산용)
    server_timestamp_us: u64,
}
```

### 중복 전송 비율 (Forward Redundancy)

| 네트워크 상태 | 중복률 | 용도 |
|---------------|--------|------|
| 안정적 | 5~15% | 로컬/데이터센터 |
| 약간 불안정 | 20~35% | 일반 인터넷 |
| 불안정 | 40~60% | 모바일/위성 |
| 극한 환경 | 70%+ | 고손실 환경 |

## 🔧 설정 옵션

```rust
use sfp::Config;

// 기본 설정
let config = Config::default();

// 저사양 기기용
let config = Config::low_spec();

// 고성능용
let config = Config::high_performance();

// 불안정 네트워크용
let config = Config::unstable_network();

// 커스텀 설정
let mut config = Config::new();
config.chunk_size = 1200;
config.segment_size = 65536;
config.base_redundancy_ratio = 0.20; // 20%
```

## 📐 실효 처리율 공식

```
real_throughput = raw_bandwidth × (1 - loss_rate) × (1 - redundancy_ratio)
```

- `raw_bandwidth`: 물리적 대역폭
- `loss_rate`: 패킷 손실률
- `redundancy_ratio`: 중복 전송 비율

## 🎯 장점 (vs TCP/QUIC)

| 환경 | SFP | TCP | QUIC |
|------|-----|-----|------|
| 저사양 기기 | ✅ 매우 빠름 | ❌ ACK 오버헤드 | ⚠️ 복잡성 |
| 고손실 환경 | ✅ 중복으로 보정 | ❌ 재전송 지연 | ⚠️ RTT 의존 |
| 멀티패스 | ✅ NIC별 비율 조정 | ❌ 미지원 | ⚠️ 제한적 |
| 국제 회선 (높은 RTT) | ✅ RTT 무관 | ❌ 심각한 지연 | ⚠️ 영향 받음 |

## 📁 라이브러리 사용 예시

### 서버 (송신자)

```rust
use sfp::{Config, Sender, PathManager};
use std::sync::Arc;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let config = Config::default();
    let path_manager = Arc::new(PathManager::new(config.clone()));
    let sender = Sender::new(config, path_manager);
    
    sender.start("0.0.0.0:9000".parse()?).await?;
    Ok(())
}
```

### 클라이언트 (수신자)

```rust
use sfp::{Config, receiver::Receiver, PathManager};
use std::sync::Arc;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let config = Config::default();
    let path_manager = Arc::new(PathManager::new(config.clone()));
    
    let (receiver, mut segment_rx) = Receiver::start(
        config,
        "0.0.0.0:0".parse()?,
        "127.0.0.1:9000".parse()?,
        path_manager,
    ).await?;
    
    while let Some((segment_id, data)) = segment_rx.recv().await {
        println!("Received segment {}: {} bytes", segment_id, data.len());
    }
    
    Ok(())
}
```

## 🔬 핵심 구성 요소

### 1. NACK 기반 블록 전송
- **ACK 없음** → 클라이언트 업링크 부담 최소화
- **누락 청크만 요청** → 필요한 것만 재전송
- **청크 캐싱** → 세그먼트별 청크를 메모리에 보관, 재전송 시 재분할/재암호화 불필요

```rust
// 서버: 세그먼트 청크 캐시
let segment_chunks: HashMap<u64, Vec<Chunk>> = HashMap::new();

// NACK 수신 시 캐시에서 바로 재전송
if let Some(chunks) = segment_chunks.get(&nack.segment_id) {
    for &chunk_id in &nack.missing_chunk_ids {
        if let Some(chunk) = chunks.get(chunk_id as usize) {
            socket.send(&chunk.to_bytes()).await?;
        }
    }
}
```

### 2. X25519 + ChaCha20-Poly1305 암호화
- **키 교환**: X25519 ECDH (Init/InitAck에서 공개키 교환)
- **대칭 암호화**: ChaCha20-Poly1305 (세그먼트 단위 암호화)
- **선택적 활성화**: `--encrypt` 플래그로 on/off

```rust
// 암호화 세션 생성
let keypair = EphemeralKeyPair::generate();
let session = CryptoSession::from_key_exchange(&keypair, &peer_public_key);

// 세그먼트 암호화
let encrypted = session.encrypt_segment(segment_id, &plaintext);
```

### 3. BBR-lite 혼잡 제어
```rust
pub struct BbrLite {
    pub pacing_rate: f64,      // bytes/sec (초기 300MB/s)
    pub min_rtt: f64,          // 최소 RTT 추적
    pub last_rtt: f64,         // 최근 RTT
    pub delivered_bytes: u64,  // 누적 전송량
    pub gain: f64,             // 동적 gain (queue_ratio 기반)
    pub probe_interval: f64,   // 갱신 주기 (200ms)
}

// 전송 시 호출
bbr.on_packet_sent(bytes);

// RTT 샘플 수신 시
bbr.on_rtt_update(measured_rtt);

// 주기적으로 rate 갱신 (btlbw * gain 기반)
bbr.update_rate();
```

### 4. 백프레셔 (Backpressure)
```rust
// 송신 큐 용량 기반 자동 흐름 제어
const QUEUE_CAPACITY: usize = 200_000;
const MIN_CAPACITY: usize = 70_000;     // 이 이하면 대기
const RESUME_CAPACITY: usize = 190_000; // 이 이상이면 재개

// 데이터 생성 루프
while tx.capacity() < MIN_CAPACITY {
    tokio::time::sleep(Duration::from_millis(10)).await;
}
// capacity >= RESUME_CAPACITY 이면 전송 재개
```

### 5. FlowControl 피드백
```rust
// 클라이언트 → 서버 (주기적)
struct FlowControlMessage {
    buffer_available: u32,      // 수신 버퍼 여유
    last_completed_segment: u64,
    segments_in_progress: u32,
    loss_rate: f32,             // 최근 손실률
    processing_rate: f32,       // 처리 속도 (seg/sec)
    suggested_rate: f32,        // 권장 전송 속도
}
```

### 6. Forward Redundancy
- **RTT 의존 없음** → 재전송 대기 없이 선제적 중복 전송
- **동적 조정** → 손실률에 따라 중복률 자동 증가/감소
- **Redundant Chunk** → 원본과 동일한 청크를 추가 전송

## 📜 라이선스

MIT License

---

**이 프로토콜은 TCP/QUIC의 다음 세대를 향한 새로운 방향을 제시합니다.**
