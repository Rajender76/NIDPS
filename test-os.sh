#!/usr/bin/env bash
for flags in S A F SA SF; do
  sudo hping3 -$flags -p 80 -c 1 192.152.15.1 -I lo
  sleep 1            # 1 s gap ⇒ total < 20 s
done
