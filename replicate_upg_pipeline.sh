
#!/bin/bash

# Replication script for Autel UPG full extraction pipeline (using combined fixed extractor)

INPUT="$1"
OUTDIR="replicated_output"
SUMMARY="extracted_upg_summary.csv"

mkdir -p $OUTDIR

# Run fixed combined extractor
python3 autel_upg_extractor_combined_fixed.py -i "$INPUT" -o $OUTDIR -s $SUMMARY

echo "✔ Extraction pipeline complete."
