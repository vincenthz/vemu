#!/bin/sh
# Guest side of scripts/e2e.sh, installed as /etc/vemu-test.sh in the e2e
# initramfs. /init runs it (after DHCP and the disk listing) when the kernel
# command line has vemu.test=1. The scenario and its parameters come from the
# command line: e2e=NAME and e2e.KEY=VALUE. Results are "e2e: ..." lines that
# the host side checks.

# The initramfs links only a few applets; make the rest available.
/bin/busybox --install -s /bin 2>/dev/null

arg() {
  for a in $(cat /proc/cmdline); do
    case $a in "e2e.$1="*) echo "${a#*=}"; return ;; esac
  done
}
say() { echo "e2e: $*"; }
md5() { md5sum "$1" | awk '{print $1}'; }
# Random file of $2 MiB at $1.
mkrandom() { dd if=/dev/urandom of="$1" bs=1048576 count="$2" 2>/dev/null; }
# What the disk holds where disk-write writes: the first 16 bytes, sector
# 2048 (the marker, padded with zeros) and the 16 MiB at 8 MiB, as md5s.
show_disk() {
  say "head $(head -c 16 /dev/vda)"
  say "sector md5=$(dd if=/dev/vda bs=512 skip=2048 count=1 2>/dev/null | md5sum | awk '{print $1}')"
  say "bulk md5=$(dd if=/dev/vda bs=1048576 skip=8 count=16 2>/dev/null | md5sum | awk '{print $1}')"
}

# Wait (up to 10 s) until every TCP connection on local port $1 has had all
# its data and its FIN acknowledged: powering off sooner would drop what is
# still in the socket's send queue.
drain_tcp() {
  n=0
  while [ $n -lt 100 ] && netstat -tn | awk -v p=":$1" '
      $4 ~ p"$" && ($3 > 0 || $6 == "FIN_WAIT1" || $6 == "CLOSING" || $6 == "LAST_ACK") { busy = 1 }
      END { exit !busy }'; do
    sleep 0.1
    n=$((n + 1))
  done
}

# One-shot HTTP/1.0 server on port $1 serving file $2 (nc -e runs it per
# connection). The request headers are read in full before answering so the
# close does not turn into a reset.
serve_http() {
  cat > /tmp/serve.sh <<SERVE
#!/bin/sh
cr=\$(printf '\r')
while read -r line; do
  case "\$line" in "" | "\$cr") break ;; esac
done
printf 'HTTP/1.0 200 OK\r\nContent-Type: application/octet-stream\r\nContent-Length: %s\r\nConnection: close\r\n\r\n' \$(wc -c < "$2")
cat "$2"
SERVE
  chmod +x /tmp/serve.sh
  nc -l -p "$1" -e /tmp/serve.sh
}

scenario=$(arg scenario)
case $scenario in
disk-read)
  say "marker $(head -c 16 /dev/vda)"
  ;;
disk-write)
  # A marker at sector 2048, then 16 MiB of random data at 8 MiB.
  printf '%s' "$(arg marker)" > /tmp/marker
  dd if=/tmp/marker of=/dev/vda bs=512 seek=2048 conv=sync,fsync 2>/dev/null && say "marker written"
  mkrandom /tmp/bulk 16
  dd if=/tmp/bulk of=/dev/vda bs=1048576 seek=8 conv=fsync 2>/dev/null && say "bulk written md5=$(md5 /tmp/bulk)"
  # Read it back through the device, bypassing the page cache we just filled.
  echo 3 > /proc/sys/vm/drop_caches
  dd if=/dev/vda of=/tmp/back bs=1048576 skip=8 count=16 2>/dev/null
  say "bulk readback md5=$(md5 /tmp/back)"
  ;;
disk-show)
  show_disk
  ;;
disk-mark)
  # What is there, then a new marker in sector 2048.
  show_disk
  printf '%s' "$(arg marker)" > /tmp/marker
  dd if=/tmp/marker of=/dev/vda bs=512 seek=2048 conv=sync,fsync 2>/dev/null && say "marker written"
  ;;
disk-ro)
  echo x > /tmp/x
  if dd if=/tmp/x of=/dev/vda bs=512 seek=2048 conv=sync,fsync 2>/dev/null; then w=accepted; else w=rejected; fi
  say "ro=$(cat /sys/block/vda/ro) write=$w"
  ;;
ping)
  say "ping $(ping -c 3 -W 2 10.0.2.2 | grep -o '[0-9]* packets received')"
  ;;
dns)
  out=$(nslookup "$(arg name)" 10.0.2.3 2>&1)
  echo "$out"
  addr=$(echo "$out" | awk '/^Name:/ {n=1} n && /^Address/ && $NF ~ /^[0-9.]+$/ {print $NF; exit}')
  say "dns ${addr:-none}"
  ;;
http-get)
  url=http://10.0.2.2:$(arg port)/$(arg file)
  if wget -q -O /tmp/get "$url"; then say "get md5=$(md5 /tmp/get) size=$(wc -c < /tmp/get)"; else say "get failed"; fi
  ;;
http-parallel)
  # $n concurrent downloads of the same file.
  url=http://10.0.2.2:$(arg port)/$(arg file)
  n=$(arg n)
  i=0
  while [ $i -lt "$n" ]; do
    (wget -q -O /tmp/par.$i "$url" && md5 /tmp/par.$i > /tmp/par.$i.md5; rm -f /tmp/par.$i) &
    i=$((i + 1))
  done
  wait
  say "parallel $(cat /tmp/par.*.md5 | wc -l) $(cat /tmp/par.*.md5 | sort -u | tr '\n' ' ')"
  ;;
http-post)
  # busybox wget sends --post-file as a C string, so post base64 text.
  mkrandom /tmp/raw "$(arg mib)"
  base64 /tmp/raw > /tmp/up
  say "post local md5=$(md5 /tmp/up)"
  say "post local size=$(wc -c < /tmp/up)"
  if wget -q -O /tmp/resp --post-file /tmp/up "http://10.0.2.2:$(arg port)/upload"; then
    say "post remote $(cat /tmp/resp)"
  else
    say "post failed"
  fi
  ;;
hostfwd-http)
  mkrandom /tmp/www "$(arg mib)"
  say "serving md5=$(md5 /tmp/www)"
  serve_http 8080 /tmp/www
  drain_tcp 8080
  say "served"
  ;;
hostfwd-udp)
  nc -u -l -p 5353 > /tmp/udp &
  pid=$!
  say "udp listening"
  n=0
  while [ $n -lt 200 ] && [ ! -s /tmp/udp ]; do sleep 0.1; n=$((n + 1)); done
  kill $pid 2>/dev/null
  say "udp got $(head -n 1 /tmp/udp)"
  ;;
hostfwd-shell)
  say "shell listening"
  nc -l -p 2323 -e /bin/sh
  drain_tcp 2323
  say "shell closed"
  ;;
internet)
  if wget -q -T 10 -O /tmp/page "http://$(arg host)/"; then
    say "internet $(grep -c 'Example Domain' /tmp/page) matches"
  else
    say "internet failed"
  fi
  ;;
sleep)
  t0=$(cut -d' ' -f1 /proc/uptime)
  say "t0"
  sleep 2
  say "t1 uptime $t0 $(cut -d' ' -f1 /proc/uptime)"
  ;;
rtc)
  # The kernel set the clock from rtc0 at boot (CONFIG_RTC_HCTOSYS).
  r=/sys/class/rtc/rtc0
  # Per-CPU counts only: they stop at the controller name (the hwirq after
  # it is a number too).
  irqs() { awk '/pl031/ { s = 0; for (i = 2; i <= NF && $i ~ /^[0-9]+$/; i++) s += $i; print s; exit }' /proc/interrupts; }
  say "rtc name $(cat $r/name 2>/dev/null || echo none)"
  say "rtc time $(cat $r/since_epoch 2>/dev/null || echo 0) sys $(date +%s)"
  # An alarm 2 s ahead must raise the PL031 interrupt.
  before=$(irqs)
  echo 0 > $r/wakealarm 2>/dev/null
  echo +2 > $r/wakealarm 2>/dev/null || say "rtc wakealarm write failed"
  # Nothing may fire early (an early match would re-arm and fire twice).
  sleep 1
  early=$(irqs)
  sleep 2
  say "rtc alarm irqs ${before:-none} $(irqs) early=${early:-none} pending=[$(cat $r/wakealarm 2>/dev/null)]"
  ;;
idle)
  sleep "$(arg seconds)"
  say "idle done"
  ;;
smp)
  # One md5 worker per CPU over the same data; all must agree.
  n=$(grep -c ^processor /proc/cpuinfo)
  i=0
  while [ $i -lt "$n" ]; do
    (dd if=/dev/zero bs=1048576 count=64 2>/dev/null | md5sum | awk '{print $1}' > /tmp/smp.$i) &
    i=$((i + 1))
  done
  wait
  say "smp $(cat /tmp/smp.* | sort -u | tr '\n' ' ')"
  ;;
hotplug)
  # Offline and online every secondary CPU a few times (PSCI CPU_OFF and
  # CPU_ON on vCPUs that already ran), then use them all.
  cpus=$(seq 1 $(($(nproc) - 1)))
  ok=0
  for round in 1 2 3; do
    for c in $cpus; do echo 0 > /sys/devices/system/cpu/cpu$c/online; done
    [ "$(cat /sys/devices/system/cpu/online)" = 0 ] || say "offline round $round: $(cat /sys/devices/system/cpu/online)"
    for c in $cpus; do echo 1 > /sys/devices/system/cpu/cpu$c/online; done
    [ "$(cat /sys/devices/system/cpu/online)" = "0-$(($(nproc) - 1))" ] && ok=$((ok + 1))
  done
  say "hotplug rounds ok=$ok online=$(cat /sys/devices/system/cpu/online)"
  ;;
"")
  ;;
*)
  say "unknown scenario $scenario"
  ;;
esac
