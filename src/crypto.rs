//! 암호화 모듈 - X25519 키 교환 + ChaCha20-Poly1305 대칭 암호화
//!
//! 흐름:
//! 1. 양측이 X25519 키쌍 생성
//! 2. 공개키 교환
//! 3. 공유 비밀(shared secret) 계산
//! 4. ChaCha20-Poly1305로 세그먼트 암호화/복호화

use chacha20poly1305::{
    aead::{Aead, KeyInit},
    ChaCha20Poly1305, Nonce,
};
use rand_core::OsRng;
use serde::{Deserialize, Serialize};
use x25519_dalek::{EphemeralSecret, PublicKey, StaticSecret};

/// X25519 공개키 (32 bytes)
pub const PUBLIC_KEY_SIZE: usize = 32;

/// ChaCha20-Poly1305 nonce 크기 (12 bytes)
pub const NONCE_SIZE: usize = 12;

/// ChaCha20-Poly1305 태그 크기 (16 bytes)
pub const TAG_SIZE: usize = 16;

/// 암호화 오류
#[derive(Debug, thiserror::Error)]
pub enum CryptoError {
    #[error("키 교환 실패")]
    KeyExchangeFailed,
    #[error("암호화 실패: {0}")]
    EncryptionFailed(String),
    #[error("복호화 실패: {0}")]
    DecryptionFailed(String),
    #[error("잘못된 키 크기")]
    InvalidKeySize,
    #[error("잘못된 nonce")]
    InvalidNonce,
}

/// 키 교환을 위한 공개키 메시지
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KeyExchangeMessage {
    pub public_key: [u8; PUBLIC_KEY_SIZE],
}

impl KeyExchangeMessage {
    pub fn to_bytes(&self) -> Vec<u8> {
        bincode::serialize(self).unwrap_or_default()
    }

    pub fn from_bytes(bytes: &[u8]) -> Option<Self> {
        bincode::deserialize(bytes).ok()
    }
}

/// 서버/클라이언트 측 키쌍 (장기 키)
pub struct KeyPair {
    secret: StaticSecret,
    public: PublicKey,
}

impl KeyPair {
    /// 새 키쌍 생성
    pub fn generate() -> Self {
        let secret = StaticSecret::random_from_rng(OsRng);
        let public = PublicKey::from(&secret);
        Self { secret, public }
    }

    /// 공개키 반환
    pub fn public_key(&self) -> &PublicKey {
        &self.public
    }

    /// 공개키를 바이트로 변환
    pub fn public_key_bytes(&self) -> [u8; PUBLIC_KEY_SIZE] {
        *self.public.as_bytes()
    }

    /// 상대방 공개키로 공유 비밀 계산
    pub fn compute_shared_secret(&self, peer_public: &[u8; PUBLIC_KEY_SIZE]) -> [u8; 32] {
        let peer_public = PublicKey::from(*peer_public);
        let shared = self.secret.diffie_hellman(&peer_public);
        *shared.as_bytes()
    }
}

/// 임시 키쌍 (일회성 세션용)
pub struct EphemeralKeyPair {
    secret: EphemeralSecret,
    public: PublicKey,
}

impl EphemeralKeyPair {
    /// 새 임시 키쌍 생성
    pub fn generate() -> Self {
        let secret = EphemeralSecret::random_from_rng(OsRng);
        let public = PublicKey::from(&secret);
        Self { secret, public }
    }

    /// 공개키 반환
    pub fn public_key(&self) -> &PublicKey {
        &self.public
    }

    /// 공개키를 바이트로 변환
    pub fn public_key_bytes(&self) -> [u8; PUBLIC_KEY_SIZE] {
        *self.public.as_bytes()
    }

    /// 상대방 공개키로 공유 비밀 계산 (소비됨)
    pub fn compute_shared_secret(self, peer_public: &[u8; PUBLIC_KEY_SIZE]) -> [u8; 32] {
        let peer_public = PublicKey::from(*peer_public);
        let shared = self.secret.diffie_hellman(&peer_public);
        *shared.as_bytes()
    }
}

/// 세그먼트 암호화기
pub struct SegmentCipher {
    cipher: ChaCha20Poly1305,
    nonce_counter: u64,
}

impl SegmentCipher {
    /// 공유 비밀로 암호화기 생성
    pub fn new(shared_secret: &[u8; 32]) -> Self {
        let cipher = ChaCha20Poly1305::new_from_slice(shared_secret)
            .expect("Invalid key size");
        Self {
            cipher,
            nonce_counter: 0,
        }
    }

    /// 다음 nonce 생성 (segment_id 기반)
    fn generate_nonce(&mut self, segment_id: u64) -> [u8; NONCE_SIZE] {
        let mut nonce = [0u8; NONCE_SIZE];
        // segment_id를 nonce로 사용 (8 bytes)
        nonce[..8].copy_from_slice(&segment_id.to_le_bytes());
        // 카운터 추가 (4 bytes)
        nonce[8..].copy_from_slice(&(self.nonce_counter as u32).to_le_bytes());
        self.nonce_counter += 1;
        nonce
    }

    /// 특정 nonce로 생성
    fn nonce_from_segment(segment_id: u64, counter: u32) -> [u8; NONCE_SIZE] {
        let mut nonce = [0u8; NONCE_SIZE];
        nonce[..8].copy_from_slice(&segment_id.to_le_bytes());
        nonce[8..].copy_from_slice(&counter.to_le_bytes());
        nonce
    }

    /// 세그먼트 암호화
    /// 반환: nonce(12) + ciphertext(원본 + 16바이트 태그)
    pub fn encrypt_segment(&mut self, segment_id: u64, plaintext: &[u8]) -> Result<Vec<u8>, CryptoError> {
        let nonce_bytes = self.generate_nonce(segment_id);
        let nonce = Nonce::from_slice(&nonce_bytes);

        let ciphertext = self.cipher
            .encrypt(nonce, plaintext)
            .map_err(|e| CryptoError::EncryptionFailed(e.to_string()))?;

        // nonce + ciphertext 형태로 반환
        let mut result = Vec::with_capacity(NONCE_SIZE + ciphertext.len());
        result.extend_from_slice(&nonce_bytes);
        result.extend_from_slice(&ciphertext);
        Ok(result)
    }

    /// 세그먼트 복호화
    /// 입력: nonce(12) + ciphertext
    pub fn decrypt_segment(&self, encrypted: &[u8]) -> Result<Vec<u8>, CryptoError> {
        if encrypted.len() < NONCE_SIZE + TAG_SIZE {
            return Err(CryptoError::DecryptionFailed("데이터가 너무 짧음".into()));
        }

        let nonce = Nonce::from_slice(&encrypted[..NONCE_SIZE]);
        let ciphertext = &encrypted[NONCE_SIZE..];

        self.cipher
            .decrypt(nonce, ciphertext)
            .map_err(|e| CryptoError::DecryptionFailed(e.to_string()))
    }

    /// segment_id와 counter로 특정 세그먼트 복호화
    pub fn decrypt_segment_with_id(
        &self,
        segment_id: u64,
        counter: u32,
        ciphertext: &[u8],
    ) -> Result<Vec<u8>, CryptoError> {
        let nonce_bytes = Self::nonce_from_segment(segment_id, counter);
        let nonce = Nonce::from_slice(&nonce_bytes);

        self.cipher
            .decrypt(nonce, ciphertext)
            .map_err(|e| CryptoError::DecryptionFailed(e.to_string()))
    }
}

/// 암호화 세션 (양방향)
pub struct CryptoSession {
    /// 세그먼트 암호화/복호화기
    pub cipher: SegmentCipher,
    /// 자신의 공개키
    pub local_public_key: [u8; PUBLIC_KEY_SIZE],
    /// 상대방 공개키
    pub peer_public_key: [u8; PUBLIC_KEY_SIZE],
}

impl CryptoSession {
    /// 새 세션 시작 (키쌍 생성)
    pub fn new() -> (EphemeralKeyPair, [u8; PUBLIC_KEY_SIZE]) {
        let keypair = EphemeralKeyPair::generate();
        let public_key = keypair.public_key_bytes();
        (keypair, public_key)
    }

    /// 키 교환 완료 및 세션 생성
    pub fn establish(
        keypair: EphemeralKeyPair,
        peer_public_key: [u8; PUBLIC_KEY_SIZE],
    ) -> Self {
        let local_public_key = keypair.public_key_bytes();
        let shared_secret = keypair.compute_shared_secret(&peer_public_key);
        let cipher = SegmentCipher::new(&shared_secret);

        Self {
            cipher,
            local_public_key,
            peer_public_key,
        }
    }

    /// 세그먼트 암호화
    pub fn encrypt(&mut self, segment_id: u64, data: &[u8]) -> Result<Vec<u8>, CryptoError> {
        self.cipher.encrypt_segment(segment_id, data)
    }

    /// 세그먼트 복호화
    pub fn decrypt(&self, encrypted: &[u8]) -> Result<Vec<u8>, CryptoError> {
        self.cipher.decrypt_segment(encrypted)
    }
}

impl Default for CryptoSession {
    fn default() -> Self {
        // 테스트용 기본 세션 (실제 사용 시 키 교환 필요)
        let keypair = EphemeralKeyPair::generate();
        let fake_peer = keypair.public_key_bytes();
        Self::establish(keypair, fake_peer)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_key_exchange() {
        // Alice와 Bob 키쌍 생성
        let alice = EphemeralKeyPair::generate();
        let bob = EphemeralKeyPair::generate();

        let alice_public = alice.public_key_bytes();
        let bob_public = bob.public_key_bytes();

        // 공유 비밀 계산 (양측이 같은 값을 얻어야 함)
        let alice_shared = alice.compute_shared_secret(&bob_public);
        let bob_shared = bob.compute_shared_secret(&alice_public);

        assert_eq!(alice_shared, bob_shared);
    }

    #[test]
    fn test_encrypt_decrypt() {
        // 세션 설정
        let alice_keypair = EphemeralKeyPair::generate();
        let bob_keypair = EphemeralKeyPair::generate();

        let alice_public = alice_keypair.public_key_bytes();
        let bob_public = bob_keypair.public_key_bytes();

        let mut alice_session = CryptoSession::establish(alice_keypair, bob_public);
        let bob_session = CryptoSession::establish(bob_keypair, alice_public);

        // 테스트 데이터
        let plaintext = b"Hello, SLS Protocol! This is encrypted data.";
        let segment_id = 1u64;

        // Alice가 암호화
        let encrypted = alice_session.encrypt(segment_id, plaintext).unwrap();

        // Bob이 복호화
        let decrypted = bob_session.decrypt(&encrypted).unwrap();

        assert_eq!(plaintext.as_slice(), decrypted.as_slice());
    }

    #[test]
    fn test_large_segment_encryption() {
        let alice_keypair = EphemeralKeyPair::generate();
        let bob_keypair = EphemeralKeyPair::generate();

        let alice_public = alice_keypair.public_key_bytes();
        let bob_public = bob_keypair.public_key_bytes();

        let mut alice_session = CryptoSession::establish(alice_keypair, bob_public);
        let bob_session = CryptoSession::establish(bob_keypair, alice_public);

        // 64KB 세그먼트
        let plaintext: Vec<u8> = (0..65536).map(|i| (i % 256) as u8).collect();

        let encrypted = alice_session.encrypt(1, &plaintext).unwrap();
        let decrypted = bob_session.decrypt(&encrypted).unwrap();

        assert_eq!(plaintext, decrypted);
    }
}
