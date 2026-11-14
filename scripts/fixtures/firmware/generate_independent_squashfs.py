"""
Independent SquashFS 4.0 binary fixture generator.
Generates an independent, spec-compliant SquashFS 4.0 image using Python standard library (struct + zlib).
"""
import struct
import zlib
import time
import sys
from pathlib import Path

def create_independent_squashfs(output_path: Path):
    block_size = 4096
    files = [
        ("etc/kernel_version", b"Linux 6.6.1-rea\n", False, None),
        ("bin/init_service", b"\x7fELF\x02\x01\x01\x00" + b"\x00"*8 + struct.pack("<HH", 2, 0x3e) + b"\x00"*44, False, None), # x86_64 ELF
        ("bin/sh", b"", True, "init_service"), # Symlink
    ]

    data_chunks = []
    file_offsets = {}
    current_data_offset = 96 # Start right after 96-byte superblock

    for path, content, is_symlink, _ in files:
        if is_symlink:
            continue
        # Uncompressed file data block (bit 24 = 1)
        file_offsets[path] = (current_data_offset, len(content))
        data_chunks.append(content)
        current_data_offset += len(content)

    # Inode table
    inode_table_offset = current_data_offset
    inode_chunks = []
    file_inode_offsets = {}
    inode_counter = 0

    for path, content, is_symlink, target in files:
        if is_symlink:
            target_bytes = target.encode("ascii")
            # Basic symlink inode: type(2), mode(2), uid(2), gid(2), mtime(4), inode_num(4), nlink(4), size(4), target
            inode = struct.pack("<HHHHIIII", 3, 0o777, 0, 0, 0, 1, 1, len(target_bytes)) + target_bytes
            file_inode_offsets[path] = inode_counter
            inode_chunks.append(inode)
            inode_counter += len(inode)
        else:
            fo_offset, fo_size = file_offsets[path]
            # Basic regular file inode: type(2), mode(2), uid(2), gid(2), mtime(4), inode_num(4), blocks_start(4), frag_idx(4), frag_offset(4), size(4), block_size(4)
            # block_size has bit 24 = 1 (uncompressed)
            inode = struct.pack("<HHHHIIIIIII", 2, 0o644, 0, 0, 0, 1, fo_offset, 0xffffffff, 0, fo_size, fo_size | (1 << 24))
            file_inode_offsets[path] = inode_counter
            inode_chunks.append(inode)
            inode_counter += len(inode)

    # Directory table
    dir_chunks = []
    dir_header = struct.pack("<III", len(files) - 1, 0, 1) # count-1, start_inode_block, inode_num
    dir_chunks.append(dir_header)

    for path, _, is_symlink, _ in files:
        name_bytes = path.encode("ascii")
        in_off = file_inode_offsets[path]
        # Entry header is 8 bytes: inode_offset (2), type (2), name_size-1 (2), unused/inode_diff (2)
        entry = struct.pack("<HHHH", in_off, 3 if is_symlink else 2, len(name_bytes) - 1, 0) + name_bytes
        dir_chunks.append(entry)

    dir_table_raw = b"".join(dir_chunks)

    # Root directory inode (placed at end of inode table)
    root_inode_offset = inode_counter
    # Directory inode: type(2), mode(2), uid(2), gid(2), mtime(4), inode_num(4), dir_block_start(4), nlink(4), file_size(2), offset(2), parent_inode(4)
    root_inode = struct.pack("<HHHHIIIIHHI", 1, 0o755, 0, 0, int(time.time()), 2, 0, 2, len(dir_table_raw) + 3, 0, 1)
    inode_chunks.append(root_inode)

    inode_table_raw = b"".join(inode_chunks)
    # Uncompressed metadata block header: bit 15 = 1
    inode_table_block = struct.pack("<H", len(inode_table_raw) | 0x8000) + inode_table_raw

    # Directory table block
    directory_table_offset = inode_table_offset + len(inode_table_block)
    dir_table_block = struct.pack("<H", len(dir_table_raw) | 0x8000) + dir_table_raw

    total_bytes_used = directory_table_offset + len(dir_table_block)

    # Superblock (96 bytes)
    sb = struct.pack(
        "<IIIIIHHHHHHQQQQQQQQ",
        0x73717368,               # s_magic
        len(files) + 1,           # inodes
        int(time.time()),         # mkfs_time
        block_size,               # block_size
        0,                        # fragments
        1,                        # compression = 1 (gzip)
        12,                       # block_log = 12 (4096)
        0,                        # flags
        1,                        # id_count
        4,                        # version_major
        0,                        # version_minor
        root_inode_offset,        # root_inode_ref
        total_bytes_used,         # bytes_used
        total_bytes_used,         # id_table_start
        0xffffffffffffffff,       # xattr_id_table_start
        inode_table_offset,       # inode_table_start
        directory_table_offset,   # directory_table_start
        0xffffffffffffffff,       # fragment_table_start
        0xffffffffffffffff,       # export_table_start
    )

    full_image = sb + b"".join(data_chunks) + inode_table_block + dir_table_block
    output_path.write_bytes(full_image)
    return len(full_image)

if __name__ == "__main__":
    out = Path(sys.argv[1]) if len(sys.argv) > 1 else Path("independent_squashfs.bin")
    size = create_independent_squashfs(out)
    print(f"Generated independent SquashFS 4.0 fixture: {out} ({size} bytes)")
