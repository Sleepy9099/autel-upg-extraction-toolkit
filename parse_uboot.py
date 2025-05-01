import struct
import os
import argparse
from datetime import datetime

def parse_full_uimage_header(data, offset):
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
        "header_size": 64
    }

def parse_struct_table_until_terminator(data, start_offset, output_dir):
    os.makedirs(output_dir, exist_ok=True)
    log_path = os.path.join(output_dir, "combined_struct_and_uimage_log.txt")
    struct_fmt = "<64s16s16sIII20s"
    struct_size = struct.calcsize(struct_fmt)

    index = 0
    offset = start_offset
    results = []

    with open(log_path, "w") as log_file:
        while offset + struct_size <= len(data):
            entry = data[offset:offset + struct_size]
            if all(b == 0 for b in entry):
                break

            bin_name, name, memtype, size, unk, ptr, zeros = struct.unpack(struct_fmt, entry)

            bin_name = bin_name.split(b'\x00')[0].decode(errors="replace")
            name = name.split(b'\x00')[0].decode(errors="replace")
            memtype = memtype.split(b'\x00')[0].decode(errors="replace")

            if ptr + size > len(data) or size == 0:
                offset += struct_size
                continue

            safe_bin_name = bin_name.replace("/", "_").replace(" ", "_")
            out_path = os.path.join(output_dir, f"{index:02}_{safe_bin_name}.bin")
            with open(out_path, "wb") as out_file:
                out_file.write(data[ptr:ptr + size])

            log_file.write(
                f"Entry {index} @ 0x{offset:X}\n"
                f"  Bin Name:   {bin_name}\n"
                f"  Name:       {name}\n"
                f"  Memtype:    {memtype}\n"
                f"  Size:       {size} bytes\n"
                f"  Unk:        0x{unk:X}\n"
                f"  Data Ptr:   0x{ptr:X}\n"
                f"  Output:     {out_path}\n"
            )

            if ptr + 64 <= len(data) and struct.unpack(">I", data[ptr:ptr + 4])[0] == 0x27051956:
                try:
                    hdr = parse_full_uimage_header(data, ptr)
                    ts = datetime.utcfromtimestamp(hdr["timestamp"]).strftime('%Y-%m-%d_%H%M%S')
                    uimage_dir = os.path.join(output_dir, f"uimage_{index:02}_{hdr['name'].replace(' ', '_')}_{ts}")
                    os.makedirs(uimage_dir, exist_ok=True)

                    image_out_path = os.path.join(uimage_dir, "uimage_payload.bin")
                    with open(image_out_path, "wb") as uimg_out:
                        uimg_out.write(data[ptr + 64: ptr + 64 + hdr["size"]])

                    log_file.write(
                        f"  U-Boot uImage Header Detected:\n"
                        f"    Name:        {hdr['name']}\n"
                        f"    Type:        {hdr['image_type']}\n"
                        f"    Size:        {hdr['size']} bytes\n"
                        f"    Timestamp:   {ts}\n"
                        f"    Load Addr:   0x{hdr['load_address']:08X}\n"
                        f"    Entry Point: 0x{hdr['entry_point']:08X}\n"
                        f"    Data CRC:    0x{hdr['data_crc']:08X}\n"
                        f"    Head CRC:    0x{hdr['header_crc']:08X}\n"
                        f"    Extracted To:{image_out_path}\n"
                    )
                except Exception as e:
                    log_file.write(f"  Failed to parse uImage header: {e}\n")

            log_file.write("\n")
            results.append((bin_name, ptr, size, out_path))
            offset += struct_size
            index += 1

    return log_path, results

def main():
    parser = argparse.ArgumentParser(description="Parse structure table and extract uImage headers.")
    parser.add_argument("-i", "--input", required=True, help="Path to input binary image")
    parser.add_argument("-o", "--offset", required=False, default="0xD0", help="Start offset of the structure table (hex or decimal)")
    parser.add_argument("-d", "--dir", default="output_structs", help="Directory to write carved files and logs")
    args = parser.parse_args()

    offset = int(args.offset, 0)

    with open(args.input, "rb") as f:
        data = f.read()

    log_path, _ = parse_struct_table_until_terminator(data, offset, args.dir)
    print(f"[+] Log saved to {log_path}")

if __name__ == "__main__":
    main()
