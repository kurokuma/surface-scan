use anyhow::{Context, Result, bail};
use serde::{Deserialize, Serialize};
use std::{collections::BTreeSet, net::Ipv4Addr, path::Path};

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct Checkpoint {
    pub schema_version: String,
    pub target_set_hash: String,
    pub port_spec: String,
    pub completed_hosts: BTreeSet<Ipv4Addr>,
    pub discovered_open_ports: std::collections::BTreeMap<Ipv4Addr, Vec<u16>>,
    pub protocol_probe_completed: BTreeSet<Ipv4Addr>,
    pub output_position: u64,
}
impl Checkpoint {
    pub fn fresh(hash: String, ports: String) -> Self {
        Self {
            schema_version: "1".into(),
            target_set_hash: hash,
            port_spec: ports,
            ..Default::default()
        }
    }
    pub fn load(path: &Path, expected_hash: &str, expected_ports: &str) -> Result<Self> {
        let cp: Self = serde_json::from_slice(
            &std::fs::read(path).with_context(|| format!("read checkpoint {}", path.display()))?,
        )?;
        if cp.target_set_hash != expected_hash {
            bail!("checkpoint target set does not match current targets")
        }
        if cp.port_spec != expected_ports {
            bail!("checkpoint ports do not match current selection")
        }
        Ok(cp)
    }
    pub fn save(&self, path: &Path) -> Result<()> {
        let temporary = path.with_extension("state.tmp");
        std::fs::write(&temporary, serde_json::to_vec_pretty(self)?)
            .with_context(|| format!("write checkpoint {}", temporary.display()))?;
        std::fs::rename(&temporary, path)
            .with_context(|| format!("commit checkpoint {}", path.display()))?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn checkpoint_round_trip() {
        let d = tempfile::tempdir().unwrap();
        let p = d.path().join("x.state");
        let cp = Checkpoint::fresh("abc".into(), "80".into());
        cp.save(&p).unwrap();
        assert_eq!(
            Checkpoint::load(&p, "abc", "80").unwrap().target_set_hash,
            "abc"
        );
    }
}
