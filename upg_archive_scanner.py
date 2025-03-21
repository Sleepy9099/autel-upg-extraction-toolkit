
#!/usr/bin/env python3

import os
import argparse
import zipfile
import tarfile
import lzma
import shutil

def scan_and_extract_archives(input_dir, output_dir):
    os.makedirs(output_dir, exist_ok=True)
    summary = []

    for root, _, files in os.walk(input_dir):
        for file in files:
            full_path = os.path.join(root, file)
            with open(full_path, "rb") as f:
                header = f.read(512)

            detected = None
            extracted = False
            try:
                if header.startswith(b'PK\x03\x04'):
                    detected = "ZIP"
                    zip_out = os.path.join(output_dir, file + "_unzipped")
                    os.makedirs(zip_out, exist_ok=True)
                    with zipfile.ZipFile(full_path, 'r') as zip_ref:
                        zip_ref.extractall(zip_out)
                    extracted = True

                elif header.startswith(b"\xfd7zXZ\x00") or header.startswith(b"\x5d\x00\x00"):
                    detected = "LZMA"
                    lzma_out = os.path.join(output_dir, file + ".decompressed")
                    with open(lzma_out, "wb") as out_f:
                        with lzma.open(full_path) as lz:
                            shutil.copyfileobj(lz, out_f)
                    extracted = True

                elif tarfile.is_tarfile(full_path):
                    detected = "TAR"
                    tar_out = os.path.join(output_dir, file + "_untarred")
                    os.makedirs(tar_out, exist_ok=True)
                    with tarfile.open(full_path, 'r') as tar:
                        tar.extractall(path=tar_out)
                    extracted = True

                elif b'Yaffs' in header or b'yaffs2' in header.lower():
                    detected = "YAFFS2 (heuristic match)"
                    extracted = False

            except Exception as e:
                detected = f"Error: {e}"

            summary.append({
                "File": full_path,
                "Detected Type": detected or "Unknown",
                "Extracted": extracted
            })

    return summary

def main():
    parser = argparse.ArgumentParser(description="Scan extracted UPG files for embedded archives (ZIP, LZMA, TAR, YAFFS2)")
    parser.add_argument("-i", "--input", required=True, help="Path to scan (extracted files folder)")
    parser.add_argument("-o", "--output", required=True, help="Path to save extracted content")
    args = parser.parse_args()

    summary = scan_and_extract_archives(args.input, args.output)

    print("\n=== Archive Scan Summary ===")
    for s in summary:
        print(f"{s['File']} → {s['Detected Type']} (Extracted: {s['Extracted']})")

if __name__ == "__main__":
    main()
