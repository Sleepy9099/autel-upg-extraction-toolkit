
#!/usr/bin/env python3

import os
import hashlib
import pandas as pd
import argparse
import errno

def mkdir_p(path):
    try:
        os.makedirs(path)
    except OSError as exc:
        if exc.errno != errno.EEXIST or not os.path.isdir(path):
            raise

def safe_open_w(path):
    mkdir_p(os.path.dirname(path))
    return open(path, 'wb')

def bytes_to_hex_str(byte_arr):
    return ' '.join('{:02x}'.format(x) for x in byte_arr)

def parse_entries_with_summary(data, output_folder, summary_csv_path):
    filetransfer = b'\x22\x3C\x66\x69\x6C\x65\x74\x72\x61\x6E\x73\x66\x65\x72\x3E\x22'
    fileinfo = b'\x22\x3C\x66\x69\x6C\x65\x69\x6E\x66\x6F\x3E\x22'
    filecontent = b'\x22\x3C\x66\x69\x6C\x65\x63\x6F\x6E\x74\x65\x6E\x74\x3E\x22'
    entry_count = 0
    summary_records = []

    while True:
        transfer_start = data.find(filetransfer)
        if transfer_start == -1:
            break

        data = data[transfer_start + len(filetransfer):]
        info_start = data.find(fileinfo)
        if info_start == -1:
            break
        data = data[info_start + len(fileinfo):]

        if len(data) < 8:
            break
        field_size = int.from_bytes(data[:4], 'big')
        unknown_info = data[4:8]
        if len(data) < 8 + field_size:
            break
        filename_bytes = data[8:8 + field_size]
        filename = filename_bytes.decode('ascii', errors='replace')
        data = data[8 + field_size:]

        content_start = data.find(filecontent)
        if content_start == -1:
            break
        data = data[content_start + len(filecontent):]

        if len(data) < 8:
            break
        field_size = int.from_bytes(data[:4], 'big')
        unknown_content = data[4:8]
        if len(data) < 8 + field_size:
            break
        file_data = data[8:8 + field_size]
        data = data[8 + field_size:]

        save_path = os.path.join(output_folder, filename)
        with safe_open_w(save_path) as out_file:
            out_file.write(file_data)

        md5_hash = hashlib.md5(file_data).hexdigest()

        summary_records.append({
            "Entry": entry_count,
            "Filename": filename,
            "File Size": len(file_data),
            "MD5 Hash": md5_hash,
            "Unknown Info": bytes_to_hex_str(unknown_info),
            "Unknown Content": bytes_to_hex_str(unknown_content),
            "Saved Path": save_path
        })

        entry_count += 1

    # Save summary CSV
    df = pd.DataFrame(summary_records)
    df.to_csv(summary_csv_path, index=False)
    print(f"[✓] Extracted {entry_count} files.")
    print(f"[✓] Summary CSV saved to: {summary_csv_path}")

def main():
    parser = argparse.ArgumentParser(description="Corrected Autel UPG firmware extractor with MD5 verification and CSV summary")
    parser.add_argument("-i", "--input", required=True, help="Input firmware binary file")
    parser.add_argument("-o", "--output", required=True, help="Output folder for extracted files")
    parser.add_argument("-s", "--summary", default="extracted_upg_summary.csv", help="Summary CSV output path")
    args = parser.parse_args()

    with open(args.input, "rb") as f:
        firmware_data = f.read()

    parse_entries_with_summary(firmware_data, args.output, args.summary)

if __name__ == "__main__":
    main()
