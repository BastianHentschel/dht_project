#!/bin/bash
cargo build -Zunstable-options --release --out-dir build && pytest
