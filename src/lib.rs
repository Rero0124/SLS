//! # SFP (Segment Flow Protocol)
//!
//! UDP 기반 NACK 블록 조립형 전송 프로토콜
//!
//! ## 핵심 특징
//! - **NACK 기반**: ACK 없이 missing chunk만 요청
//! - **블록 조립**: Segment를 Chunk로 분할, 퍼즐처럼 조립
//! - **Forward Redundancy**: 중복 전송으로 손실 보정
//! - **멀티패스**: 여러 NIC로 동시 전송, 비율 자동 조정
//! - **저사양 최적화**: 클라이언트 부담 최소화
//! - **BBR-lite 혼잡제어**: RTT/대역폭 기반 동적 pacing
//! - **백프레셔**: 큐 기반 자동 흐름 제어

pub mod chunk;
pub mod config;
pub mod crypto;
pub mod error;
pub mod message;
pub mod multipath;
pub mod receiver;
pub mod sender;
pub mod stats;
pub mod bbr;

pub use chunk::{Chunk, ChunkId, Segment, SegmentId, SegmentBuilder};
pub use config::Config;
pub use crypto::{CryptoSession, EphemeralKeyPair, KeyExchangeMessage, SegmentCipher};
pub use error::{Error, Result};
pub use message::{Message, NackMessage};
pub use multipath::{NicInfo, PathManager};
pub use receiver::Receiver;
pub use sender::Sender;
pub use stats::TransferStats;

/// 프로토콜 버전
pub const PROTOCOL_VERSION: u8 = 1;

/// 기본 청크 크기 (바이트)
pub const DEFAULT_CHUNK_SIZE: usize = 1200;

/// 기본 세그먼트 크기 (바이트)
pub const DEFAULT_SEGMENT_SIZE: usize = 65536; // 64KB

/// 매직 넘버 (패킷 식별용)
pub const MAGIC_NUMBER: u32 = 0x53465050; // "SFPP"
