# Changelog

All notable changes to this project will be documented in this file.

## [1.1.0] - 2025-03-21

### Added
- `autel_upg_extractor_combined_fixed.py`: Combined top-level and recursive extractor (single script).
- `upg_archive_scanner.py`: Companion tool to scan for embedded archive formats (ZIP, LZMA, TAR, YAFFS2).
- CSV summary output logging for all extractions.
- GitHub-friendly support files:
  - `README.md` with usage examples and format diagram
  - `LICENSE` (MIT)
  - `CONTRIBUTING.md`
  - `CHANGELOG.md`
  - `requirements.txt` and `pyproject.toml` for easy setup
  - `upg_format_layout_diagram.png`

### Changed
- Refactored pipeline shell script: now uses only the combined extractor.
- Enhanced tag matching with corrected hex byte detection.

### Fixed
- Previous extractor failures caused by ASCII vs hex tag mismatch.

## [1.0.0] - 2025-03-20
### Added
- Initial release of Autel UPG Extraction Toolkit
- Top-level UPG extractor script
- Recursive filecontent extractor with nested scanning
- Archive format scanner (ZIP, LZMA, TAR, YAFFS2 heuristic)
- Full automated pipeline shell script
- Markdown README with format diagram
- MIT License, CONTRIBUTING.md, requirements.txt, and pyproject.toml

### Improvements
- Recursive scanning now checks each file extracted from `<filecontent>` blocks
- CSV summary files generated for each stage

### Known Limitations
- YAFFS2 files are only flagged, not mounted or parsed
- Assumes UPG block structure based on known hex-tag formats