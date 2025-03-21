# Autel UPG Extraction Toolkit

A complete toolkit for parsing and recursively extracting files from Autel UPG firmware packages, including archive detection and validation.

## 📂 Included Tools

- `autel_upg_extractor_combined_fixed.py`: Combined top-level and recursive extractor (latest version)
- `upg_archive_scanner.py`: Scanner for embedded archive formats (ZIP, LZMA, TAR, YAFFS2 heuristic)
- `replicate_upg_pipeline.sh`: Shell pipeline script to automate the full process
- `requirements.txt`, `pyproject.toml`: Easy installation and Python packaging
- `CHANGELOG.md`, `CONTRIBUTING.md`, `LICENSE`: Project documentation and guidelines

## 📐 UPG Format Layout

The structure of Autel UPG firmware files is illustrated below:

![UPG Format Layout](upg_format_layout_diagram.png)

## 🛠 Requirements

- Python 3.6+
- pandas

Install required packages:
```bash
pip install -r requirements.txt
```

## ▶ Usage Examples

### Run extractor manually
```bash
python3 autel_upg_extractor_combined_fixed.py -i Model-C_FW_V2.7.25.bin -o extracted_upg -s summary.csv
```

### Run archive scan
```bash
python3 upg_archive_scanner.py -i extracted_upg -o archive_output
```

### Run full pipeline
```bash
chmod +x replicate_upg_pipeline.sh
./replicate_upg_pipeline.sh Model-C_FW_V2.7.25.bin
```

## 🔁 Recursive Extraction Support

Files extracted from `<filecontent>` blocks are also scanned for nested `<filetransfer>` structures automatically.

## 💡 Notes

- Archive detection is based on magic byte matching.
- YAFFS2 support is limited to heuristic flagging.
- All extracted data is saved to structured output directories with full metadata logs.

## 📄 License

This project is licensed under the MIT License.