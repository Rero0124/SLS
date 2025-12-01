# SLS (Super Light Stream) Protocol

UDP 기반 **NACK 블록 조립형** 전송 프로토콜 - Rust 구현

## 🔥 핵심 철학

- **NACK 기반**: ACK 없음, 누락된 청크만 요청
- **블록/퍼즐 조립**: 스트림이 아닌 세그먼트 단위 전송
- **Forward Redundancy**: 중복 전송으로 손실 보정
- **저사양 최적화**: 클라이언트 부담 최소화

## 📦 구조

```
SLS/
├── src/
│   ├── lib.rs           # 라이브러리 진입점
│   ├── chunk.rs         # Segment/Chunk 정의
│   ├── config.rs        # 프로토콜 설정
│   ├── error.rs         # 에러 타입
│   ├── message.rs       # 프로토콜 메시지 (NACK 등)
│   ├── multipath.rs     # 멀티패스 관리
│   ├── receiver.rs      # 수신자 (클라이언트)
│   ├── sender.rs        # 송신자 (서버)
│   ├── stats.rs         # 전송 통계
│   └── bin/
│       ├── server.rs    # 서버 실행 파일
│       └── client.rs    # 클라이언트 실행 파일
└── Cargo.toml
```

## 🚀 빌드 및 실행

```bash
# 빌드
cargo build --release

# 서버 실행 (송신자)
cargo run --release --bin sls-server -- --bind 0.0.0.0:9000 --file data.bin

# 클라이언트 실행 (수신자)
cargo run --release --bin sls-client -- --server 127.0.0.1:9000 --output received.bin
```

## 📊 프로토콜 개요

### 전송 단위

| 단위 | 크기 | 설명 |
|------|------|------|
| **Segment** | 64KB ~ 128KB | 논리적 블록, 조립 단위 |
| **Chunk** | 1100 ~ 1400 bytes | UDP 패킷 단위, 퍼즐 조각 |

### 데이터 흐름

```
서버 (송신자)                          클라이언트 (수신자)
     │                                      │
     │──── Chunk (segment_id, chunk_id) ───>│
     │──── Chunk (중복 전송 포함) ─────────>│
     │──── Chunk ──────────────────────────>│
     │                                      │
     │<──── NACK (missing chunk IDs) ───────│ (누락시에만)
     │                                      │
     │──── 재전송 Chunk ───────────────────>│
     │                                      │
     │<──── SegmentComplete ────────────────│
```

### 중복 전송 비율 (Forward Redundancy)

| 네트워크 상태 | 중복률 |
|---------------|--------|
| 안정적 | 5~15% |
| 약간 불안정 | 20~35% |
| 불안정 | 40~60% |
| 극한 환경 | 70%+ |

## 🔧 설정 옵션

```rust
use sls::Config;

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

| 환경 | SLS | TCP | QUIC |
|------|-----|-----|------|
| 저사양 기기 | ✅ 매우 빠름 | ❌ ACK 오버헤드 | ⚠️ 복잡성 |
| 고손실 환경 | ✅ 중복으로 보정 | ❌ 재전송 지연 | ⚠️ RTT 의존 |
| 멀티패스 | ✅ NIC별 비율 조정 | ❌ 미지원 | ⚠️ 제한적 |
| 국제 회선 (높은 RTT) | ✅ RTT 무관 | ❌ 심각한 지연 | ⚠️ 영향 받음 |

## 📁 라이브러리 사용 예시

### 서버 (송신자)

```rust
use sls::{Config, Sender, PathManager};
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
use sls::{Config, receiver::Receiver, PathManager};
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
- ACK 없음 → 클라이언트 부담 최소화
- 누락 청크만 요청 → 업링크 최소화

### 2. PUEC (Punctual Unequal Chunking) 멀티패스
- NIC별 속도 측정 (chunk arrival rate)
- 자동 비율 조정
- 손실률 기반 중복률 계산

### 3. Forward Redundancy
- RTT 의존 없음
- 실시간 고손실 대응
- 네트워크 상태에 따른 동적 조정

## 📜 라이선스

MIT License

---

**이 프로토콜은 TCP/QUIC의 다음 세대를 향한 새로운 방향을 제시합니다.**
