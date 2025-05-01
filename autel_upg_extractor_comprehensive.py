#!/usr/bin/env python3

import os
import re
import struct
import hashlib
import argparse
import tarfile
import zipfile
import magic

def identify_file_type(filepath):
    try:
        ms = magic.Magic(mime=False)
        return ms.from_file(filepath)
    except Exception as e:
        return f"Error identifying type: {e}"

from pathlib import Path
from datetime import datetime
import logging

def setup_logging(log_path):
    logging.basicConfig(
        filename=log_path,
        level=logging.INFO,
        format="%(asctime)s [%(levelname)s] %(message)s",
    )
    console = logging.StreamHandler()
    console.setLevel(logging.INFO)
    formatter = logging.Formatter("[%(levelname)s] %(message)s")
    console.setFormatter(formatter)
    logging.getLogger().addHandler(console)

import io
import tarfile
import zipfile
import gzip
import lzma



def detect_and_extract_compression(data, output_dir, base_name):
    os.makedirs(output_dir, exist_ok=True)

    if data[:2] == b'\x1f\x8b':  # gzip or tar.gz
        try:
            with gzip.GzipFile(fileobj=io.BytesIO(data)) as gz:
                decompressed = gz.read()
                inner_name = os.path.basename(gz.name) if gz.name else base_name.replace('.gz', '')
            out_path = os.path.join(output_dir, clean_filename(inner_name))
            with open(out_path, 'wb') as f:
                f.write(decompressed)
            if tarfile.is_tarfile(out_path):
                logging.info(f"[ARCHIVE] Detected tar archive in: {out_path}")
                with tarfile.open(out_path, "r") as tar:
                    tar.extractall(output_dir)
                    for member in tar.getnames():
                        logging.info(f"[TAR] Extracted: {member}")
            elif b'\x22\x3C\x66\x69\x6C\x65\x74\x72\x61\x6E\x73\x66\x65\x72\x3E\x22' in decompressed:
                logging.info(f"[RECURSE] Scanning decompressed file for UPG structure: {out_path}")
                extract_upg_and_parse_uboot(decompressed, os.path.dirname(out_path))
            return "gzip", out_path
        except Exception as e:
            return f"gzip_failed: {e}", None

    elif data[:4] == b'PK\x03\x04':  # zip
        try:
            zip_path = os.path.join(output_dir, clean_filename(base_name))
            with open(zip_path, "wb") as f:
                f.write(data)
            with zipfile.ZipFile(zip_path, 'r') as zip_ref:
                zip_ref.extractall(output_dir)
                for name in zip_ref.namelist():
                    logging.info(f"[ZIP] Extracted: {name}")
            return "zip", zip_path
        except Exception as e:
            return f"zip_failed: {e}", None

    elif data[:2] == b'\x5d\x00':  # lzma
        try:
            decompressed = lzma.decompress(data)
            out_path = os.path.join(output_dir, base_name.replace('.lzma', ''))
            with open(out_path, 'wb') as f:
                f.write(decompressed)
            if b'\x22\x3C\x66\x69\x6C\x65\x74\x72\x61\x6E\x73\x66\x65\x72\x3E\x22' in decompressed:
                logging.info(f"[RECURSE] Scanning decompressed file for UPG structure: {out_path}")
                extract_upg_and_parse_uboot(decompressed, os.path.dirname(out_path))
            return "lzma", out_path
        except Exception as e:
            return f"lzma_failed: {e}", None

    elif data[:6] == b'\xfd7zXZ\x00':  # xz
        try:
            decompressed = lzma.decompress(data, format=lzma.FORMAT_XZ)
            out_path = os.path.join(output_dir, base_name.replace('.xz', ''))
            with open(out_path, 'wb') as f:
                f.write(decompressed)
            if b'\x22\x3C\x66\x69\x6C\x65\x74\x72\x61\x6E\x73\x66\x65\x72\x3E\x22' in decompressed:
                logging.info(f"[RECURSE] Scanning decompressed file for UPG structure: {out_path}")
                extract_upg_and_parse_uboot(decompressed, os.path.dirname(out_path))
            return "xz", out_path
        except Exception as e:
            return f"xz_failed: {e}", None

    return "none", None

def clean_filename(name):
    return re.sub(r'[^a-zA-Z0-9._-]', '_', name)

def parse_uimage_header(data, offset):
    try:
        header_fmt = ">IIIIIII4B32s"
        fields = struct.unpack(header_fmt, data[offset:offset + 64])
        return {
            "magic": fields[0],
            "header_crc": fields[1],
            "timestamp": fields[2],
            "size": fields[3],
            "load_address": fields[4],
            "entry_point": fields[5],
            "data_crc": fields[6],
            "os_type": fields[7],
            "arch": fields[8],
            "image_type": fields[9],
            "compression": fields[10],
            "name": fields[11].rstrip(b'\x00').decode("ascii", errors="replace"),
        }
    except:
        return None

def extract_upg_and_parse_uboot(data, output_dir):
    def parse_entries(data, output_folder, summary_records=None, recursion_level=0, parent_path="root"):
        if summary_records is None:
            summary_records = []

        filetransfer = b'\x22\x3C\x66\x69\x6C\x65\x74\x72\x61\x6E\x73\x66\x65\x72\x3E\x22'
        fileinfo = b'\x22\x3C\x66\x69\x6C\x65\x69\x6E\x66\x6F\x3E\x22'
        filecontent = b'\x22\x3C\x66\x69\x6C\x65\x63\x6F\x6E\x74\x65\x6E\x74\x3E\x22'

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

            subfolder = os.path.join(output_folder, parent_path.replace('/', '_'))
            os.makedirs(subfolder, exist_ok=True)
            save_path = os.path.join(subfolder, filename)
            logging.info(f"[UPG] Writing extracted file: {save_path}")
            logging.info(f"[UPG] Offset {position} | Size {content_field_size}")
            logging.info(f"[UPG] Extracting: {filename} | Offset: {position}, Size: {content_field_size}")
            with open(save_path, 'wb') as out_file:
                out_file.write(file_data)
                comp_type, comp_path = detect_and_extract_compression(file_data, subfolder, filename)
                if comp_type != 'none':
                    logging.info(f"Decompressed {comp_type} file to: {comp_path}")

            md5_hash = hashlib.md5(file_data).hexdigest()

            summary_records.append({
                "Recursion Level": recursion_level,
                "Parent": parent_path,
                "Entry": entry_count,
                "Filename": filename,
                "File Size": len(file_data),
                "MD5 Hash": md5_hash,
                "Saved Path": save_path
            })

            if filetransfer in file_data:
                inner_output = os.path.join(subfolder, f"{filename}_nested")
                parse_entries(file_data, inner_output, summary_records, recursion_level + 1, parent_path + '/' + filename)

            entry_count += 1

        return summary_records

    return parse_entries(data, output_dir)

def run_upg_and_parse_uboot_structs_nested(data, output_dir):
    os.makedirs(output_dir, exist_ok=True)
    upg_dir = os.path.join(output_dir, "upg_extracted")
    os.makedirs(upg_dir, exist_ok=True)

    upg_summary = extract_upg_and_parse_uboot(data, upg_dir)

    struct_fmt = "<64s16s16sIII20s"
    struct_size = struct.calcsize(struct_fmt)

    for entry in upg_summary:
        bin_path = entry["Saved Path"]
        if not os.path.isfile(bin_path):
            continue
        with open(bin_path, "rb") as f:
            file_data = f.read()

        offset = 0xD0
        index = 0

        # Create nested scan folder inside the same extracted directory
        nested_base = os.path.join(os.path.dirname(bin_path), "uimage_scans")
        os.makedirs(nested_base, exist_ok=True)

        logging.info(f"[STRUCT] Scanning struct table at offset 0x{offset:X}")
        while offset + struct_size <= len(file_data):
            entry_data = file_data[offset:offset + struct_size]
            if all(b == 0 for b in entry_data):
                break

            bin_name, name, memtype, size, unk, ptr, _ = struct.unpack(struct_fmt, entry_data)
            try:
                bin_name_raw = bin_name.split(b'\x00')[0]
                name_raw = name.split(b'\x00')[0]
                bin_name = clean_filename(bin_name_raw.decode('ascii'))
                name_decoded = name_raw.decode('ascii')
            except UnicodeDecodeError:
                offset += struct_size
                index += 1
                continue

            if ptr + size > len(file_data) or size == 0:
                offset += struct_size
                continue

            bin_out_path = os.path.join(nested_base, f"{index:02}_{bin_name}.bin")
            logging.info(f"[STRUCT] Extracted entry to: {bin_out_path} (offset 0x{ptr:X}, size {size})")
            logging.info(f"[STRUCT] Entry {index}: {bin_name} | Ptr: 0x{ptr:X} | Size: {size}")
            with open(bin_out_path, "wb") as out_bin:
                out_bin.write(file_data[ptr:ptr + size])

            if file_data[ptr:ptr+4] == b'\x27\x05\x19\x56':
                uimg = parse_uimage_header(file_data, ptr)
                if uimg:
                    ts = datetime.utcfromtimestamp(uimg["timestamp"]).strftime("%Y-%m-%d_%H%M%S")
                    uimage_name = clean_filename(uimg["name"])
                    uimg_dir = os.path.join(nested_base, f"uimage_{index:02}_{uimage_name}_{ts}")
                    os.makedirs(uimg_dir, exist_ok=True)
                    logging.info(f"[UIMAGE] Offset 0x{ptr:X}: Name={uimg['name']}, Size={uimg['size']}, Load=0x{uimg['load_address']:08X}, Entry=0x{uimg['entry_point']:08X}")
                    uimg_file = os.path.join(uimg_dir, f"{clean_filename(uimg['name'])}.bin")
                    with open(uimg_file, "wb") as u:
                        u.write(file_data[ptr+64:ptr+64+uimg["size"]])

            offset += struct_size
            index += 1

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Extract UPG contents and scan for nested uImage headers")
    parser.add_argument("-i", "--input", required=True, help="Path to Autel firmware .bin file")
    parser.add_argument("-o", "--output", required=True, help="Directory to extract output")
    args = parser.parse_args()
    os.makedirs(args.output, exist_ok=True)  # Ensure output directory exists
    log_file = os.path.join(args.output, "extraction.log")
    setup_logging(log_file)

    logging.info("Started extraction")

    with open(args.input, "rb") as f:
        header_preview = f.read(64)
        logging.info(f"[HEADER] First 64 bytes: {header_preview.hex()}")
        f.seek(0)
        data = f.read()

        run_upg_and_parse_uboot_structs_nested(data, args.output)
