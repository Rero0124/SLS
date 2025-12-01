//! 에러 타입 정의

use thiserror::Error;

/// SLS 프로토콜 에러 타입
#[derive(Error, Debug)]
pub enum Error {
    #[error("IO 에러: {0}")]
    Io(#[from] std::io::Error),

    #[error("직렬화 에러: {0}")]
    Serialization(#[from] bincode::Error),

    #[error("유효하지 않은 매직 넘버: expected {expected:08X}, got {got:08X}")]
    InvalidMagicNumber { expected: u32, got: u32 },

    #[error("유효하지 않은 프로토콜 버전: expected {expected}, got {got}")]
    InvalidVersion { expected: u8, got: u8 },

    #[error("세그먼트 타임아웃: segment_id={segment_id}")]
    SegmentTimeout { segment_id: u64 },

    #[error("청크 누락: segment_id={segment_id}, missing_chunks={missing_count}")]
    ChunksMissing {
        segment_id: u64,
        missing_count: usize,
    },

    #[error("버퍼 오버플로우: 최대 크기 {max_size} 초과")]
    BufferOverflow { max_size: usize },

    #[error("유효하지 않은 청크 ID: {chunk_id}")]
    InvalidChunkId { chunk_id: u32 },

    #[error("유효하지 않은 세그먼트 ID: {segment_id}")]
    InvalidSegmentId { segment_id: u64 },

    #[error("CRC 불일치: expected {expected:08X}, got {got:08X}")]
    CrcMismatch { expected: u32, got: u32 },

    #[error("NIC 없음")]
    NoNicAvailable,

    #[error("채널 에러")]
    ChannelError,

    #[error("연결 종료")]
    ConnectionClosed,

    #[error("메시지 타입 불일치: expected {expected}, got {got}")]
    MessageTypeMismatch { expected: String, got: String },

    #[error("알 수 없는 에러: {0}")]
    Unknown(String),
}

/// Result 타입 별칭
pub type Result<T> = std::result::Result<T, Error>;
