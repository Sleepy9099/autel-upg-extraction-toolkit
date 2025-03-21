#!/bin/bash

# Replication script for Autel UPG full recursive extraction

INPUT="$1"
OUTDIR="replicated_output"
SUMMARY1="top_level_extracted_summary.csv"
SUMMARY2="recursive_subextracted_summary.csv"
SUMMARY3="recursive_deep_subextracted_summary.csv"

mkdir -p $OUTDIR

# Step 1: Top-level extraction
python3 autel_upg_extractor_corrected.py -i "$INPUT" -o $OUTDIR/top_level -s $SUMMARY1

# Step 2: Recursive scan on each top-level .bin file
for BIN in $OUTDIR/top_level/*.bin; do
    python3 autel_upg_extractor_recursive_final.py -i "$BIN" -o $OUTDIR/recursive -s $SUMMARY2
done

# Step 3: Deeper recursive scan on recursive .bin/.upg files
for NESTED in $(find $OUTDIR/recursive -type f \( -name "*.bin" -o -name "*.upg" \)); do
    python3 autel_upg_extractor_recursive_final.py -i "$NESTED" -o $OUTDIR/deeper_recursive -s $SUMMARY3
done

echo "✔ Extraction pipeline complete."


# Step 4: Archive scan of recursively extracted files
echo "[*] Scanning recursively extracted files for embedded archives..."
python3 upg_archive_scanner.py -i $OUTDIR/recursive -o $OUTDIR/archive_scanned_output
