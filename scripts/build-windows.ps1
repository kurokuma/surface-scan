$ErrorActionPreference = 'Stop'
cargo build --release --locked
cargo test --all-targets --locked
Write-Host 'Built target\release\surface-scan.exe'

