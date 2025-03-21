
#!/usr/bin/env python3

import os
import hashlib
import pandas as pd
import argparse

def mkdir_p(path):
    os.makedirs(path, exist_ok=True)

def safe_open_w(path):
    mkdir_p(os.path.dirname(path))
    return open(path, 'wb')

def bytes_to_hex_str(byte_arr):
    return ' '.join('{:02x}'.format(x) for x in byte_arr)

def parse_entries(data, output_folder, summary_records=None, recursion_level=0, parent_path="root"):
    if summary_records is None:
        summary_records = []

    filetransfer = b'\x22\x3C\x66\x69\x6C\65\74\72\61\6E\73\66\65\72\3E\x22'.decode('unicode_escape').encode()
    fileinfo = b'\x22\x3C\x66\x69\x6C\65\69\6E\66\6F\3E\x22'.decode('unicode_escape').encode()
    filecontent = b'\x22\x3C\x66\x69\x6C\65\63\6F\6E\74\65\6E\74\3E\x22'.decode('unicode_escape').encode()

    entry_count = 0
    position = 0

    while True:
        transfer_start = data.find(filetransfer, position)
        if transfer_start == -1:
            break
        position = transfer_start + len(filetransfer)

        info_start = data.find(fileinfo, position)
        if info_start == -1:
            break
        position = info_start + len(fileinfo)

        if len(data[position:]) < 8:
            break
        field_size = int.from_bytes(data[position:position+4], 'big')
        unknown_info = data[position+4:position+8]
        if len(data[position:]) < 8 + field_size:
            break
        filename_bytes = data[position+8:position+8+field_size]
        filename = filename_bytes.decode('ascii', errors='replace')
        position += 8 + field_size

        content_start = data.find(filecontent, position)
        if content_start == -1:
            break
        position = content_start + len(filecontent)

        if len(data[position:]) < 8:
            break
        content_field_size = int.from_bytes(data[position:position+4], 'big')
        unknown_content = data[position+4:position+8]
        if len(data[position:]) < 8 + content_field_size:
            break
        file_data = data[position+8:position+8+content_field_size]
        position += 8 + content_field_size

        # Save extracted file
        subfolder = os.path.join(output_folder, parent_path.replace('/', '_'))
        mkdir_p(subfolder)
        save_path = os.path.join(subfolder, filename)
        with safe_open_w(save_path) as out_file:
            out_file.write(file_data)

        md5_hash = hashlib.md5(file_data).hexdigest()

        summary_records.append({
            "Recursion Level": recursion_level,
            "Parent": parent_path,
            "Entry": entry_count,
            "Filename": filename,
            "File Size": len(file_data),
            "MD5 Hash": md5_hash,
            "Unknown Info": bytes_to_hex_str(unknown_info),
            "Unknown Content": bytes_to_hex_str(unknown_content),
            "Saved Path": save_path
        })

        # 🔁 Recursive scan inside this file's content
        if filetransfer in file_data:
            inner_output = os.path.join(subfolder, f"{filename}_nested")
            parse_entries(file_data, inner_output, summary_records, recursion_level + 1, parent_path + '/' + filename)

        entry_count += 1

    return summary_records

def main():
    parser = argparse.ArgumentParser(description="Autel UPG extractor with corrected recursion on filecontent data")
    parser.add_argument("-i", "--input", required=True, help="Input firmware binary file")
    parser.add_argument("-o", "--output", required=True, help="Output folder for extracted files")
    parser.add_argument("-s", "--summary", default="extracted_upg_recursive_summary.csv", help="Summary CSV output path")
    args = parser.parse_args()

    with open(args.input, "rb") as f:
        firmware_data = f.read()

    summary_records = parse_entries(firmware_data, args.output)
    df = pd.DataFrame(summary_records)
    df.to_csv(args.summary, index=False)
    print(f"[✓] Recursive Extraction complete. {len(summary_records)} entries extracted.")
    print(f"[✓] Summary saved to: {args.summary}")

if __name__ == "__main__":
    main()
