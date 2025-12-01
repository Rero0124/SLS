//! 청크와 세그먼트 정의
//!
//! - Segment: 큰 논리 블록 (64KB ~ 128KB)
//! - Chunk: UDP 패킷 크기의 퍼즐 조각 (1100 ~ 1300 bytes)

use bytes::{Bytes, BytesMut};
use serde::{Deserialize, Serialize};

/// 세그먼트 ID (64비트)
pub type SegmentId = u64;

/// 청크 ID (32비트, 세그먼트 내 인덱스)
pub type ChunkId = u32;

/// 청크 헤더
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChunkHeader {
    /// 세그먼트 ID
    pub segment_id: SegmentId,

    /// 청크 ID (세그먼트 내 인덱스)
    pub chunk_id: ChunkId,

    /// 세그먼트 내 총 청크 수
    pub total_chunks: u32,

    /// 세그먼트 내 오프셋 (바이트)
    pub offset: u32,

    /// 이 청크의 데이터 길이
    pub data_len: u16,

    /// 전체 세그먼트 크기
    pub segment_size: u32,

    /// NIC ID (멀티패스용)
    pub nic_id: u8,

    /// 중복 청크 여부
    pub is_redundant: bool,

    /// CRC32 체크섬
    pub crc32: u32,

    /// 타임스탬프 (마이크로초)
    pub timestamp_us: u64,
}

/// 청크 (송신 패킷 단위)
#[derive(Debug, Clone)]
pub struct Chunk {
    /// 청크 헤더
    pub header: ChunkHeader,

    /// 실제 데이터
    pub data: Bytes,
}

impl Chunk {
    /// 새 청크 생성
    pub fn new(
        segment_id: SegmentId,
        chunk_id: ChunkId,
        total_chunks: u32,
        offset: u32,
        segment_size: u32,
        data: Bytes,
        nic_id: u8,
        is_redundant: bool,
    ) -> Self {
        let crc32 = crc32fast::hash(&data);
        let timestamp_us = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_micros() as u64;

        Self {
            header: ChunkHeader {
                segment_id,
                chunk_id,
                total_chunks,
                offset,
                data_len: data.len() as u16,
                segment_size,
                nic_id,
                is_redundant,
                crc32,
                timestamp_us,
            },
            data,
        }
    }

    /// 청크를 바이트로 직렬화
    pub fn to_bytes(&self) -> Vec<u8> {
        let header_bytes = bincode::serialize(&self.header).unwrap_or_default();
        let header_len = header_bytes.len() as u16;

        let mut buf = Vec::with_capacity(2 + header_bytes.len() + self.data.len());
        buf.extend_from_slice(&header_len.to_le_bytes());
        buf.extend_from_slice(&header_bytes);
        buf.extend_from_slice(&self.data);
        buf
    }

    /// 바이트에서 청크 역직렬화
    pub fn from_bytes(bytes: &[u8]) -> Option<Self> {
        if bytes.len() < 2 {
            return None;
        }

        let header_len = u16::from_le_bytes([bytes[0], bytes[1]]) as usize;
        if bytes.len() < 2 + header_len {
            return None;
        }

        let header: ChunkHeader = bincode::deserialize(&bytes[2..2 + header_len]).ok()?;
        let data = Bytes::copy_from_slice(&bytes[2 + header_len..]);

        Some(Self { header, data })
    }

    /// CRC 검증
    pub fn verify_crc(&self) -> bool {
        crc32fast::hash(&self.data) == self.header.crc32
    }
}

/// 세그먼트 (큰 논리 블록)
#[derive(Debug)]
pub struct Segment {
    /// 세그먼트 ID
    pub id: SegmentId,

    /// 전체 데이터
    pub data: BytesMut,

    /// 예상 총 크기
    pub total_size: usize,

    /// 수신된 청크 비트맵 (chunk_id -> 수신 여부)
    received_chunks: Vec<bool>,

    /// 총 청크 수
    pub total_chunks: u32,

    /// 수신된 청크 수
    pub received_count: u32,

    /// 생성 시간
    pub created_at: std::time::Instant,
}

impl Segment {
    /// 새 세그먼트 생성 (수신측)
    pub fn new_for_receive(id: SegmentId, total_size: usize, total_chunks: u32) -> Self {
        let mut data = BytesMut::with_capacity(total_size);
        data.resize(total_size, 0);

        Self {
            id,
            data,
            total_size,
            received_chunks: vec![false; total_chunks as usize],
            total_chunks,
            received_count: 0,
            created_at: std::time::Instant::now(),
        }
    }

    /// 청크 삽입
    pub fn insert_chunk(&mut self, chunk: &Chunk) -> bool {
        let chunk_id = chunk.header.chunk_id as usize;

        // 이미 받은 청크면 무시
        if chunk_id >= self.received_chunks.len() || self.received_chunks[chunk_id] {
            return false;
        }

        // CRC 검증
        if !chunk.verify_crc() {
            return false;
        }

        // 데이터 복사
        let offset = chunk.header.offset as usize;
        let end = (offset + chunk.data.len()).min(self.total_size);
        if offset < self.total_size {
            self.data[offset..end].copy_from_slice(&chunk.data[..end - offset]);
        }

        self.received_chunks[chunk_id] = true;
        self.received_count += 1;
        true
    }

    /// 완료 여부 확인
    pub fn is_complete(&self) -> bool {
        self.received_count >= self.total_chunks
    }

    /// 누락된 청크 ID 목록 반환
    pub fn missing_chunk_ids(&self) -> Vec<ChunkId> {
        self.received_chunks
            .iter()
            .enumerate()
            .filter(|(_, &received)| !received)
            .map(|(id, _)| id as ChunkId)
            .collect()
    }

    /// 수신률 계산
    pub fn receive_ratio(&self) -> f64 {
        if self.total_chunks == 0 {
            return 0.0;
        }
        self.received_count as f64 / self.total_chunks as f64
    }

    /// 완료된 데이터 추출
    pub fn into_data(self) -> Bytes {
        self.data.freeze()
    }
}

/// 세그먼트 생성기 (송신측)
pub struct SegmentBuilder {
    chunk_size: usize,
}

impl SegmentBuilder {
    pub fn new(chunk_size: usize) -> Self {
        Self { chunk_size }
    }

    /// 데이터를 청크들로 분할
    pub fn split_into_chunks(
        &self,
        segment_id: SegmentId,
        data: &[u8],
        nic_id: u8,
    ) -> Vec<Chunk> {
        let total_chunks = (data.len() + self.chunk_size - 1) / self.chunk_size;
        let segment_size = data.len() as u32;

        data.chunks(self.chunk_size)
            .enumerate()
            .map(|(idx, chunk_data)| {
                let offset = idx * self.chunk_size;
                Chunk::new(
                    segment_id,
                    idx as ChunkId,
                    total_chunks as u32,
                    offset as u32,
                    segment_size,
                    Bytes::copy_from_slice(chunk_data),
                    nic_id,
                    false,
                )
            })
            .collect()
    }

    /// 중복 청크 생성
    pub fn create_redundant_chunks(
        &self,
        chunks: &[Chunk],
        redundancy_ratio: f64,
    ) -> Vec<Chunk> {
        use rand::seq::SliceRandom;
        let mut rng = rand::thread_rng();

        let redundant_count = (chunks.len() as f64 * redundancy_ratio).ceil() as usize;
        let mut indices: Vec<usize> = (0..chunks.len()).collect();
        indices.shuffle(&mut rng);

        indices
            .into_iter()
            .take(redundant_count)
            .map(|idx| {
                let original = &chunks[idx];
                Chunk {
                    header: ChunkHeader {
                        is_redundant: true,
                        ..original.header.clone()
                    },
                    data: original.data.clone(),
                }
            })
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_chunk_serialization() {
        let chunk = Chunk::new(
            1,
            0,
            10,
            0,
            10000,
            Bytes::from(vec![1, 2, 3, 4, 5]),
            0,
            false,
        );

        let bytes = chunk.to_bytes();
        let restored = Chunk::from_bytes(&bytes).unwrap();

        assert_eq!(chunk.header.segment_id, restored.header.segment_id);
        assert_eq!(chunk.header.chunk_id, restored.header.chunk_id);
        assert_eq!(chunk.data, restored.data);
    }

    #[test]
    fn test_segment_assembly() {
        let builder = SegmentBuilder::new(100);
        let data: Vec<u8> = (0..250).collect();
        let chunks = builder.split_into_chunks(1, &data, 0);

        assert_eq!(chunks.len(), 3);

        let mut segment = Segment::new_for_receive(1, 250, 3);

        for chunk in &chunks {
            segment.insert_chunk(chunk);
        }

        assert!(segment.is_complete());
        assert_eq!(segment.into_data().as_ref(), &data);
    }
}
