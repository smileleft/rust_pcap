# rust_pcap

## rust install

```bash
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.sh | sh
```

## tshark install

```bash
# ubuntu/debian
apt install tshark
```

## project structure

```bash
rust_pcap/
├── Cargo.toml        ← Cargo.toml
└── src/
    └── main.rs       ←  main.rs
```

## build and execute

```bash
cargo build
./target/debug/rust_pcap
```

## release build

```bash
cargo build --release
./target/release/rust_pcap
```
