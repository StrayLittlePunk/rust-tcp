#!/usr/bin/env bash

cargo b --release
# 普通用户下要设置CAP_NET_ADMIN设置tun
# sudo setcap cap_net_admin=eip $CARGO_TARGET_DIR/release/rust-tcp
target/release/rust-tcp &
pid=$!
ip addr add 192.168.108.1/24 dev tun0
ip link set up dev tun0
trap "kill $pid" INT TERM
wait $pid
