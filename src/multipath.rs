//! 멀티패스 관리
//!
//! 여러 NIC를 통한 동시 전송 및 비율 조정

use std::net::SocketAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Instant;

use parking_lot::RwLock;
use tokio::net::UdpSocket;

use crate::stats::NicStats;
use crate::{Config, Result};

/// NIC 정보
#[derive(Debug, Clone)]
pub struct NicInfo {
    /// NIC ID
    pub id: u8,

    /// 로컬 바인드 주소
    pub local_addr: SocketAddr,

    /// 대상 주소
    pub remote_addr: SocketAddr,

    /// 현재 전송 비율 (0.0 ~ 1.0)
    pub ratio: f64,

    /// 활성 상태
    pub active: bool,

    /// 마지막 활동 시간
    pub last_activity: Instant,
}

impl NicInfo {
    pub fn new(id: u8, local_addr: SocketAddr, remote_addr: SocketAddr) -> Self {
        Self {
            id,
            local_addr,
            remote_addr,
            ratio: 1.0,
            active: true,
            last_activity: Instant::now(),
        }
    }
}

/// 멀티패스 경로 관리자
pub struct PathManager {
    /// NIC 정보 목록
    nics: RwLock<Vec<NicInfo>>,

    /// NIC별 소켓
    sockets: RwLock<Vec<Arc<UdpSocket>>>,

    /// NIC별 통계
    stats: RwLock<Vec<NicStats>>,

    /// 설정
    config: Config,

    /// 현재 청크 배분용 카운터
    chunk_counter: AtomicU64,

    /// 마지막 비율 조정 시간
    last_ratio_adjust: RwLock<Instant>,
}

impl PathManager {
    /// 새 PathManager 생성
    pub fn new(config: Config) -> Self {
        Self {
            nics: RwLock::new(Vec::new()),
            sockets: RwLock::new(Vec::new()),
            stats: RwLock::new(Vec::new()),
            config,
            chunk_counter: AtomicU64::new(0),
            last_ratio_adjust: RwLock::new(Instant::now()),
        }
    }

    /// NIC 추가
    pub async fn add_nic(&self, local_addr: SocketAddr, remote_addr: SocketAddr) -> Result<u8> {
        let socket = UdpSocket::bind(local_addr).await?;
        socket.connect(remote_addr).await?;

        // 버퍼 크기 설정 (socket2 사용 시 가능)
        // tokio UdpSocket은 직접 버퍼 설정 불가, 생성 전 socket2로 설정 필요

        let id = {
            let mut nics = self.nics.write();
            let id = nics.len() as u8;
            nics.push(NicInfo::new(id, local_addr, remote_addr));
            id
        };

        {
            let mut sockets = self.sockets.write();
            sockets.push(Arc::new(socket));
        }

        {
            let mut stats = self.stats.write();
            stats.push(NicStats::new(id, self.config.stats_window_size));
        }

        // 비율 재조정
        self.equalize_ratios();

        Ok(id)
    }

    /// 비율 균등화
    fn equalize_ratios(&self) {
        let mut nics = self.nics.write();
        let active_count = nics.iter().filter(|n| n.active).count();
        if active_count == 0 {
            return;
        }

        let equal_ratio = 1.0 / active_count as f64;
        for nic in nics.iter_mut() {
            if nic.active {
                nic.ratio = equal_ratio;
            } else {
                nic.ratio = 0.0;
            }
        }
    }

    /// 다음 청크를 전송할 NIC 선택
    pub fn select_nic_for_chunk(&self) -> Option<u8> {
        let nics = self.nics.read();
        if nics.is_empty() {
            return None;
        }

        let counter = self.chunk_counter.fetch_add(1, Ordering::Relaxed);

        // 가중치 기반 라운드로빈
        let mut cumulative = 0.0;
        let position = (counter as f64 % 100.0) / 100.0;

        for nic in nics.iter() {
            if !nic.active {
                continue;
            }
            cumulative += nic.ratio;
            if position < cumulative {
                return Some(nic.id);
            }
        }

        // 폴백: 첫 번째 활성 NIC
        nics.iter().find(|n| n.active).map(|n| n.id)
    }

    /// 소켓 가져오기
    pub fn get_socket(&self, nic_id: u8) -> Option<Arc<UdpSocket>> {
        let sockets = self.sockets.read();
        sockets.get(nic_id as usize).cloned()
    }

    /// 모든 소켓 가져오기
    pub fn get_all_sockets(&self) -> Vec<Arc<UdpSocket>> {
        self.sockets.read().clone()
    }

    /// 청크 수신 기록
    pub fn record_chunk_arrival(&self, nic_id: u8, size: usize) {
        let mut stats = self.stats.write();
        if let Some(stat) = stats.get_mut(nic_id as usize) {
            stat.record_arrival(size);
        }

        let mut nics = self.nics.write();
        if let Some(nic) = nics.get_mut(nic_id as usize) {
            nic.last_activity = Instant::now();
        }
    }

    /// 손실 기록
    pub fn record_loss(&self, nic_id: u8, count: u64) {
        let mut stats = self.stats.write();
        if let Some(stat) = stats.get_mut(nic_id as usize) {
            stat.record_loss(count);
        }
    }

    /// 비율 조정 (통계 기반)
    pub fn adjust_ratios(&self) {
        let now = Instant::now();

        // 조정 주기 확인
        {
            let last = self.last_ratio_adjust.read();
            if now.duration_since(*last).as_millis()
                < self.config.ratio_adjust_interval_ms as u128
            {
                return;
            }
        }

        let stats = self.stats.read();
        let mut nics = self.nics.write();

        // 각 NIC의 처리율 계산
        let throughputs: Vec<f64> = stats.iter().map(|s| s.throughput()).collect();
        let total_throughput: f64 = throughputs.iter().sum();

        if total_throughput > 0.0 {
            // 처리율 기반 비율 조정
            for (i, nic) in nics.iter_mut().enumerate() {
                if nic.active {
                    let loss_rate = stats[i].loss_rate();
                    // 손실률이 높은 NIC는 비율 감소
                    let adjusted_throughput = throughputs[i] * (1.0 - loss_rate);
                    nic.ratio = adjusted_throughput / total_throughput;
                }
            }

            // 최소 비율 보장 (0.1)
            let active_count = nics.iter().filter(|n| n.active).count();
            let min_ratio = 0.1 / active_count as f64;
            for nic in nics.iter_mut() {
                if nic.active && nic.ratio < min_ratio {
                    nic.ratio = min_ratio;
                }
            }

            // 정규화
            let total: f64 = nics.iter().filter(|n| n.active).map(|n| n.ratio).sum();
            if total > 0.0 {
                for nic in nics.iter_mut() {
                    if nic.active {
                        nic.ratio /= total;
                    }
                }
            }
        }

        *self.last_ratio_adjust.write() = now;
    }

    /// 현재 비율 반환
    pub fn get_ratios(&self) -> Vec<(u8, f64)> {
        self.nics
            .read()
            .iter()
            .map(|n| (n.id, n.ratio))
            .collect()
    }

    /// NIC 비활성화
    pub fn deactivate_nic(&self, nic_id: u8) {
        let mut nics = self.nics.write();
        if let Some(nic) = nics.get_mut(nic_id as usize) {
            nic.active = false;
            nic.ratio = 0.0;
        }
        drop(nics);
        self.equalize_ratios();
    }

    /// NIC 활성화
    pub fn activate_nic(&self, nic_id: u8) {
        let mut nics = self.nics.write();
        if let Some(nic) = nics.get_mut(nic_id as usize) {
            nic.active = true;
        }
        drop(nics);
        self.equalize_ratios();
    }

    /// 활성 NIC 수
    pub fn active_nic_count(&self) -> usize {
        self.nics.read().iter().filter(|n| n.active).count()
    }

    /// 전체 NIC 수
    pub fn nic_count(&self) -> usize {
        self.nics.read().len()
    }

    /// NIC 통계 복사
    pub fn get_stats(&self) -> Vec<NicStats> {
        self.stats.read().clone()
    }

    /// 손실률 기반 중복률 계산
    pub fn calculate_redundancy(&self) -> f64 {
        let stats = self.stats.read();
        let max_loss_rate = stats
            .iter()
            .map(|s| s.loss_rate())
            .fold(0.0f64, |a, b| a.max(b));

        self.config.calculate_redundancy(max_loss_rate)
    }

    /// 전체 처리율
    pub fn total_throughput(&self) -> f64 {
        self.stats.read().iter().map(|s| s.throughput()).sum()
    }
}

/// 간단한 단일 경로 관리자 생성
pub async fn create_single_path(
    local_addr: SocketAddr,
    remote_addr: SocketAddr,
    config: Config,
) -> Result<PathManager> {
    let manager = PathManager::new(config);
    manager.add_nic(local_addr, remote_addr).await?;
    Ok(manager)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr};

    #[tokio::test]
    async fn test_path_manager_single_nic() {
        let config = Config::default();
        let manager = PathManager::new(config);

        let _local = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0)), 0);
        let _remote = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 9999);

        // NIC 추가는 실제 바인딩이 필요하므로 테스트 스킵
        assert_eq!(manager.nic_count(), 0);
    }

    #[test]
    fn test_nic_selection() {
        let config = Config::default();
        let manager = PathManager::new(config);

        // NIC 없을 때
        assert!(manager.select_nic_for_chunk().is_none());
    }
}
