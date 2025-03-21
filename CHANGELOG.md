# Changelog

All notable changes to this project will be documented in this file.

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