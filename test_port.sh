
for port in {22..30}; do
    sudo hping3 -S -p "$port" -c 1 127.0.0.1 -I lo
    sleep 0.3   # keep total <15 s
done