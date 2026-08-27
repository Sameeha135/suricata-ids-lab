#!/bin/bash
# generate_15_vs_5.sh
INPUT="sample_attack.pcap"
WORKDIR="mh_tmp"
OUTPUT="15_vs_5_simulation.pcap"
SURICATA_MAC="00:0c:29:9b:a0:64"

mkdir -p "$WORKDIR"
rm -f "$WORKDIR"/*.pcap

ATTACKERS=(10.0.0.1 10.0.0.2 10.0.0.3 10.0.0.4 10.0.0.5 10.0.0.6 10.0.0.7 10.0.0.8 10.0.0.9 10.0.0.10 10.0.0.11 10.0.0.12 10.0.0.13 10.0.0.14 10.0.0.15)
VICTIMS=(192.168.93.139 192.168.93.140 192.168.93.141 192.168.93.142 192.168.93.143)
REAL_CLIENT="192.168.93.130"
REAL_VICTIM="192.168.93.139"

i=0
for atk in "${ATTACKERS[@]}"; do
    vic=${VICTIMS[$(( i % 5 ))]}
    echo "[+] Building attacker $atk -> victim $vic"
    sudo tcprewrite \
      --infile="$INPUT" \
      --outfile="$WORKDIR/atk_${i}.pcap" \
      --srcipmap=${REAL_CLIENT}/32:${atk}/32,${REAL_VICTIM}/32:${vic}/32 \
      --dstipmap=${REAL_CLIENT}/32:${atk}/32,${REAL_VICTIM}/32:${vic}/32 \
      --enet-dmac="$SURICATA_MAC" \
      --fixcsum --fixhdrlen
    i=$((i+1))
done

echo "[+] Merging 15 attacker streams into one pcap..."
mergecap -w "$OUTPUT" "$WORKDIR"/atk_*.pcap

echo "[+] Verifying topology:"
tshark -r "$OUTPUT" -T fields -e ip.src -e ip.dst | sort -u
