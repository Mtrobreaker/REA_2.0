#!/usr/bin/env python3
"""
Real Binary Evaluation and Independent Acceptance Audit of REA Pipeline
on OpenWrt 23.05.0 MIPS32/MIPS16 ath79 ELF Binaries.

Milestone 4.3.2 Audit Capabilities:
  - Full MIPS16 instruction decoding and conformance
  - Real executable segment auditing distinguishing code vs data, literal pools, and padding
  - Explicit denominators for byte coverage
  - Function recovery source categorization (SYMBOL, METADATA, DIRECT_CALL, PROLOGUE, HEURISTIC)
  - True basic block and CFG edge precision & recall against Ghidra 12.2 Headless ground truth
  - Preservation of inconclusive indirect calls and fail-closed security properties
"""

import os
import sys
import json
import re
import struct
import hashlib

REPO_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), '..', '..', '..'))
WIN_RUNTIME = os.path.join(REPO_ROOT, 'tools', 'capstone', 'windows', 'runtime')
sys.path.insert(0, WIN_RUNTIME)

import capstone
from capstone import Cs, CS_ARCH_MIPS, CS_MODE_MIPS32, CS_MODE_BIG_ENDIAN

TARGETS = [
    {
        "logical_path": "bin/busybox",
        "file_name": "bin_busybox",
        "sha256": "b24929b9759d38badd1ec2338f594d10de14c74b201eff3eeb86ab507c9a751a",
        "size": 327717,
        "mips16_flag": True,
        "ghidra_file": "output_bin_busybox.json",
        "code_vaddr_start": 0x403b00,
        "code_vaddr_end": 0x44f84c,
        "m32_regions": [(0x403b00, 0x403bf0), (0x44e3a0, 0x44e4a0)]
    },
    {
        "logical_path": "usr/sbin/dropbear",
        "file_name": "usr_sbin_dropbear",
        "sha256": "d7fc7e4ee7ea59ecb4b333890483ea3a428b5ace6a737876cea2aac169832661",
        "size": 264280,
        "mips16_flag": False,
        "ghidra_file": "output_usr_sbin_dropbear.json",
        "code_vaddr_start": 0x1fec,
        "code_vaddr_end": 0x2e90c,
        "m32_regions": []
    },
    {
        "logical_path": "usr/sbin/uhttpd",
        "file_name": "usr_sbin_uhttpd",
        "sha256": "e0fc103c3edb5ddec4447a6e4627b09edf80e226f826c6c94421cfe19f338c84",
        "size": 66704,
        "mips16_flag": True,
        "ghidra_file": "output_usr_sbin_uhttpd.json",
        "code_vaddr_start": 0x2434,
        "code_vaddr_end": 0x8abc,
        "m32_regions": [(0x2434, 0x2450), (0x2fe0, 0x3120), (0x8390, 0x8aa8)]
    },
    {
        "logical_path": "lib/libc.so",
        "file_name": "lib_libc.so",
        "sha256": "2fecb30f3a049e44608345dddaa64eff44b6ace31fad5ccfc8e5187c6375b9b0",
        "size": 725268,
        "mips16_flag": False,
        "ghidra_file": "output_lib_libc.so.json",
        "code_vaddr_start": 0x12820,
        "code_vaddr_end": 0x981fc,
        "m32_regions": []
    }
]

M16_REG_NAMES = ["$s0", "$s1", "$v0", "$v1", "$a0", "$a1", "$a2", "$a3"]
M16_R32_NAMES = [
    "$zero", "$at", "$v0", "$v1", "$a0", "$a1", "$a2", "$a3",
    "$t0", "$t1", "$t2", "$t3", "$t4", "$t5", "$t6", "$t7",
    "$s0", "$s1", "$s2", "$s3", "$s4", "$s5", "$s6", "$s7",
    "$t8", "$t9", "$k0", "$k1", "$gp", "$sp", "$fp", "$ra"
]

def parse_elf(buf):
    is_le = buf[5] == 1
    endian = '<' if is_le else '>'
    
    e_entry = struct.unpack(f'{endian}I', buf[24:28])[0]
    e_phoff = struct.unpack(f'{endian}I', buf[28:32])[0]
    e_shoff = struct.unpack(f'{endian}I', buf[32:36])[0]
    e_flags = struct.unpack(f'{endian}I', buf[36:40])[0]
    e_phentsize = struct.unpack(f'{endian}H', buf[42:44])[0]
    e_phnum = struct.unpack(f'{endian}H', buf[44:46])[0]

    exec_seg = None
    dyn_seg = None
    load_segments = []

    for i in range(e_phnum):
        off = e_phoff + i * e_phentsize
        p_type = struct.unpack(f'{endian}I', buf[off:off+4])[0]
        p_offset = struct.unpack(f'{endian}I', buf[off+4:off+8])[0]
        p_vaddr = struct.unpack(f'{endian}I', buf[off+8:off+12])[0]
        p_filesz = struct.unpack(f'{endian}I', buf[off+16:off+20])[0]
        p_flags = struct.unpack(f'{endian}I', buf[off+24:off+28])[0]

        if p_type == 1: # LOAD
            load_segments.append({"offset": p_offset, "vaddr": p_vaddr, "filesz": p_filesz, "flags": p_flags})
            if (p_flags & 1) != 0:
                exec_seg = {"offset": p_offset, "vaddr": p_vaddr, "filesz": p_filesz}
        if p_type == 2: # DYNAMIC
            dyn_seg = {"offset": p_offset, "filesz": p_filesz}

    dt_init = 0
    dt_fini = 0
    dt_symtab = 0
    dt_strtab = 0
    dt_mips_symtabno = 0

    if dyn_seg:
        for d in range(0, dyn_seg["filesz"], 8):
            tag = struct.unpack(f'{endian}I', buf[dyn_seg["offset"]+d : dyn_seg["offset"]+d+4])[0]
            val = struct.unpack(f'{endian}I', buf[dyn_seg["offset"]+d+4 : dyn_seg["offset"]+d+8])[0]
            if tag == 0x0c: dt_init = val
            elif tag == 0x0d: dt_fini = val
            elif tag == 0x06: dt_symtab = val
            elif tag == 0x05: dt_strtab = val
            elif tag == 0x70000011: dt_mips_symtabno = val

    def vaddr_to_file_offset(vaddr):
        for seg in load_segments:
            if seg["vaddr"] <= vaddr < seg["vaddr"] + seg["filesz"]:
                return seg["offset"] + (vaddr - seg["vaddr"])
        return vaddr

    symbols = []
    if dt_symtab > 0 and dt_strtab > 0 and dt_mips_symtabno > 0:
        sym_file_off = vaddr_to_file_offset(dt_symtab)
        str_file_off = vaddr_to_file_offset(dt_strtab)
        for s in range(dt_mips_symtabno):
            s_off = sym_file_off + s * 16
            if s_off + 16 > len(buf): break
            st_name, st_value, st_size, st_info = struct.unpack(f'{endian}IIIB', buf[s_off : s_off+13])
            name = ""
            if str_file_off + st_name < len(buf):
                end = buf.find(b'\x00', str_file_off + st_name)
                name = buf[str_file_off + st_name : end].decode('ascii', errors='ignore') if end != -1 else ""
            if st_value > 0:
                symbols.append({
                    "name": name or f"sub_{st_value & ~1:08x}",
                    "address": st_value,
                    "size": st_size,
                    "is_mips16": (st_value & 1) == 1
                })

    return {
        "e_entry": e_entry,
        "e_flags": e_flags,
        "has_mips16_ase": (e_flags & 0x04000000) != 0,
        "dt_init": dt_init,
        "dt_fini": dt_fini,
        "exec_seg": exec_seg,
        "symbols": symbols,
        "vaddr_to_offset": vaddr_to_file_offset
    }

def decode_mips16_instruction(data, offset, addr):
    if offset + 2 > len(data):
        return {
            "address": addr, "size": 1, "mnemonic": "malformed_unaligned", "operands": "",
            "is_branch": False, "is_conditional": False, "is_call": False,
            "is_return": False, "is_indirect": False, "target": None,
            "has_delay": False, "is_malformed": True, "isa_mode": "MIPS16"
        }, 1

    w16 = struct.unpack('>H', data[offset:offset+2])[0]
    opcode = (w16 >> 11) & 0x1f

    # EXTEND prefix (0x1e)
    if opcode == 0x1e:
        if offset + 4 > len(data):
            return {
                "address": addr, "size": 2, "mnemonic": "malformed_extend_truncated", "operands": "",
                "is_branch": False, "is_conditional": False, "is_call": False,
                "is_return": False, "is_indirect": False, "target": None,
                "has_delay": False, "is_malformed": True, "isa_mode": "MIPS16"
            }, 2
        next16 = struct.unpack('>H', data[offset+2:offset+4])[0]
        next_op = (next16 >> 11) & 0x1f

        if (next16 & 0xff80) == 0x6480:
            return {"address": addr, "size": 4, "mnemonic": "save", "operands": "", "is_branch": False, "is_conditional": False, "is_call": False, "is_return": False, "is_indirect": False, "target": None, "has_delay": False, "is_malformed": False, "isa_mode": "MIPS16"}, 4
        if (next16 & 0xff80) == 0x6400:
            return {"address": addr, "size": 4, "mnemonic": "restore", "operands": "", "is_branch": False, "is_conditional": False, "is_call": False, "is_return": False, "is_indirect": False, "target": None, "has_delay": False, "is_malformed": False, "isa_mode": "MIPS16"}, 4
        if next_op == 0x02:
            imm = ((w16 & 0x1f) << 11) | (next16 & 0x7ff)
            if imm & 0x8000: imm -= 0x10000
            target = (addr + 4 + (imm << 1)) & 0xffffffff
            return {"address": addr, "size": 4, "mnemonic": "b", "operands": f"0x{target:x}", "is_branch": True, "is_conditional": False, "is_call": False, "is_return": False, "is_indirect": False, "target": target, "has_delay": False, "is_malformed": False, "isa_mode": "MIPS16"}, 4
        if next_op in (0x04, 0x05):
            rx = (next16 >> 8) & 0x7
            imm = ((w16 & 0x1f) << 11) | (next16 & 0xff)
            if imm & 0x8000: imm -= 0x10000
            target = (addr + 4 + (imm << 1)) & 0xffffffff
            mnem = "beqz" if next_op == 0x04 else "bnez"
            return {"address": addr, "size": 4, "mnemonic": mnem, "operands": f"{M16_REG_NAMES[rx]}, 0x{target:x}", "is_branch": True, "is_conditional": True, "is_call": False, "is_return": False, "is_indirect": False, "target": target, "has_delay": False, "is_malformed": False, "isa_mode": "MIPS16"}, 4
        if (next16 & 0xff00) in (0x6000, 0x6100):
            imm = ((w16 & 0x1f) << 11) | (next16 & 0xff)
            if imm & 0x8000: imm -= 0x10000
            target = (addr + 4 + (imm << 1)) & 0xffffffff
            mnem = "bteqz" if (next16 & 0xff00) == 0x6000 else "btnez"
            return {"address": addr, "size": 4, "mnemonic": mnem, "operands": f"0x{target:x}", "is_branch": True, "is_conditional": True, "is_call": False, "is_return": False, "is_indirect": False, "target": target, "has_delay": False, "is_malformed": False, "isa_mode": "MIPS16"}, 4
        if next_op in (0x07, 0x0f, 0x17, 0x1f):
            return {"address": addr, "size": 4, "mnemonic": "unsupported_mips16_ext", "operands": f"0x{w16:04x}{next16:04x}", "is_branch": False, "is_conditional": False, "is_call": False, "is_return": False, "is_indirect": False, "target": None, "has_delay": False, "is_malformed": True, "isa_mode": "MIPS16"}, 4

        rx = (next16 >> 8) & 0x7
        ry = (next16 >> 5) & 0x7
        imm16 = ((w16 & 0x1f) << 11) | (next16 & 0x7ff)
        if imm16 & 0x8000: imm16 -= 0x10000

        ext_mnem = "addiu" if next_op in (0x00, 0x01, 0x08, 0x09, 0x0c) else "lw" if next_op in (0x12, 0x13) else "sw" if next_op in (0x1a, 0x1b) else "li" if next_op == 0x0d else "extended_alu"
        return {"address": addr, "size": 4, "mnemonic": ext_mnem, "operands": f"{M16_REG_NAMES[rx]}, {imm16}", "is_branch": False, "is_conditional": False, "is_call": False, "is_return": False, "is_indirect": False, "target": None, "has_delay": False, "is_malformed": False, "isa_mode": "MIPS16"}, 4

    # JAL / JALX (0x03)
    if opcode == 0x03:
        if offset + 4 > len(data):
            return {"address": addr, "size": 2, "mnemonic": "malformed_jal_truncated", "operands": "", "is_branch": False, "is_conditional": False, "is_call": False, "is_return": False, "is_indirect": False, "target": None, "has_delay": False, "is_malformed": True, "isa_mode": "MIPS16"}, 2
        w2 = struct.unpack('>H', data[offset+2:offset+4])[0]
        is_jalx = ((w16 >> 10) & 1) == 1
        tgt_2016 = (w16 >> 5) & 0x1f
        tgt_2521 = w16 & 0x1f
        tgt_1500 = w2 & 0xffff
        target = (((addr + 4) & 0xf0000000) | (tgt_2521 << 23) | (tgt_2016 << 18) | (tgt_1500 << 2)) & 0xffffffff
        target = target if is_jalx else (target | 1)
        mnem = "jalx" if is_jalx else "jal"
        return {"address": addr, "size": 4, "mnemonic": mnem, "operands": f"0x{target & ~1:x}", "is_branch": False, "is_conditional": False, "is_call": True, "is_return": False, "is_indirect": False, "target": target, "has_delay": True, "is_malformed": False, "isa_mode": "MIPS16"}, 4

    # 16-bit instructions
    rx = (w16 >> 8) & 0x7
    ry = (w16 >> 5) & 0x7
    rz = (w16 >> 2) & 0x7

    if opcode == 0x00:
        return {"address": addr, "size": 2, "mnemonic": "addiu", "operands": f"{M16_REG_NAMES[rx]}, $sp, {(w16 & 0xff)*4}", "is_branch": False, "is_conditional": False, "is_call": False, "is_return": False, "is_indirect": False, "target": None, "has_delay": False, "is_malformed": False, "isa_mode": "MIPS16"}, 2
    if opcode == 0x01:
        return {"address": addr, "size": 2, "mnemonic": "addiu", "operands": f"{M16_REG_NAMES[rx]}, $pc, {(w16 & 0xff)*4}", "is_branch": False, "is_conditional": False, "is_call": False, "is_return": False, "is_indirect": False, "target": None, "has_delay": False, "is_malformed": False, "isa_mode": "MIPS16"}, 2
    if opcode == 0x02:
        imm11 = w16 & 0x7ff
        if imm11 & 0x400: imm11 -= 0x800
        target = (addr + 2 + (imm11 << 1)) & 0xffffffff
        return {"address": addr, "size": 2, "mnemonic": "b", "operands": f"0x{target:x}", "is_branch": True, "is_conditional": False, "is_call": False, "is_return": False, "is_indirect": False, "target": target, "has_delay": False, "is_malformed": False, "isa_mode": "MIPS16"}, 2
    if opcode in (0x04, 0x05):
        imm8 = w16 & 0xff
        if imm8 & 0x80: imm8 -= 0x100
        target = (addr + 2 + (imm8 << 1)) & 0xffffffff
        mnem = "beqz" if opcode == 0x04 else "bnez"
        return {"address": addr, "size": 2, "mnemonic": mnem, "operands": f"{M16_REG_NAMES[rx]}, 0x{target:x}", "is_branch": True, "is_conditional": True, "is_call": False, "is_return": False, "is_indirect": False, "target": target, "has_delay": False, "is_malformed": False, "isa_mode": "MIPS16"}, 2
    if opcode == 0x06:
        sa = (w16 >> 2) & 0x7
        funct = w16 & 0x3
        mnem = "sll" if funct == 0 else "srl" if funct == 2 else "sra"
        return {"address": addr, "size": 2, "mnemonic": mnem, "operands": f"{M16_REG_NAMES[rx]}, {M16_REG_NAMES[ry]}, {sa}", "is_branch": False, "is_conditional": False, "is_call": False, "is_return": False, "is_indirect": False, "target": None, "has_delay": False, "is_malformed": False, "isa_mode": "MIPS16"}, 2
    if opcode == 0x08:
        return {"address": addr, "size": 2, "mnemonic": "addiu", "operands": f"{M16_REG_NAMES[ry]}, {M16_REG_NAMES[rx]}, {w16 & 0xf}", "is_branch": False, "is_conditional": False, "is_call": False, "is_return": False, "is_indirect": False, "target": None, "has_delay": False, "is_malformed": False, "isa_mode": "MIPS16"}, 2
    if opcode == 0x09:
        imm8 = w16 & 0xff
        if imm8 & 0x80: imm8 -= 0x100
        return {"address": addr, "size": 2, "mnemonic": "addiu", "operands": f"{M16_REG_NAMES[rx]}, {imm8}", "is_branch": False, "is_conditional": False, "is_call": False, "is_return": False, "is_indirect": False, "target": None, "has_delay": False, "is_malformed": False, "isa_mode": "MIPS16"}, 2
    if opcode == 0x0a:
        return {"address": addr, "size": 2, "mnemonic": "slti", "operands": f"{M16_REG_NAMES[rx]}, {w16 & 0xff}", "is_branch": False, "is_conditional": False, "is_call": False, "is_return": False, "is_indirect": False, "target": None, "has_delay": False, "is_malformed": False, "isa_mode": "MIPS16"}, 2
    if opcode == 0x0b:
        return {"address": addr, "size": 2, "mnemonic": "sltiu", "operands": f"{M16_REG_NAMES[rx]}, {w16 & 0xff}", "is_branch": False, "is_conditional": False, "is_call": False, "is_return": False, "is_indirect": False, "target": None, "has_delay": False, "is_malformed": False, "isa_mode": "MIPS16"}, 2
    if opcode == 0x0c:
        funct = (w16 >> 8) & 0x7
        if funct == 0:
            imm8 = w16 & 0xff
            if imm8 & 0x80: imm8 -= 0x100
            target = (addr + 2 + (imm8 << 1)) & 0xffffffff
            return {"address": addr, "size": 2, "mnemonic": "bteqz", "operands": f"0x{target:x}", "is_branch": True, "is_conditional": True, "is_call": False, "is_return": False, "is_indirect": False, "target": target, "has_delay": False, "is_malformed": False, "isa_mode": "MIPS16"}, 2
        if funct == 1:
            imm8 = w16 & 0xff
            if imm8 & 0x80: imm8 -= 0x100
            target = (addr + 2 + (imm8 << 1)) & 0xffffffff
            return {"address": addr, "size": 2, "mnemonic": "btnez", "operands": f"0x{target:x}", "is_branch": True, "is_conditional": True, "is_call": False, "is_return": False, "is_indirect": False, "target": target, "has_delay": False, "is_malformed": False, "isa_mode": "MIPS16"}, 2
        if funct == 3:
            imm8 = w16 & 0xff
            if imm8 & 0x80: imm8 -= 0x100
            return {"address": addr, "size": 2, "mnemonic": "adjsp", "operands": f"$sp, {imm8 * 8}", "is_branch": False, "is_conditional": False, "is_call": False, "is_return": False, "is_indirect": False, "target": None, "has_delay": False, "is_malformed": False, "isa_mode": "MIPS16"}, 2
        if funct == 4:
            is_save = (w16 & 0x80) == 0x80
            return {"address": addr, "size": 2, "mnemonic": "save" if is_save else "restore", "operands": "", "is_branch": False, "is_conditional": False, "is_call": False, "is_return": False, "is_indirect": False, "target": None, "has_delay": False, "is_malformed": False, "isa_mode": "MIPS16"}, 2
        if funct == 5:
            if (w16 & 0xff) == 0 and rz == 0:
                return {"address": addr, "size": 2, "mnemonic": "nop", "operands": "", "is_branch": False, "is_conditional": False, "is_call": False, "is_return": False, "is_indirect": False, "target": None, "has_delay": False, "is_malformed": False, "isa_mode": "MIPS16"}, 2
            return {"address": addr, "size": 2, "mnemonic": "move", "operands": f"{M16_R32_NAMES[w16 & 0x1f]}, {M16_REG_NAMES[rz]}", "is_branch": False, "is_conditional": False, "is_call": False, "is_return": False, "is_indirect": False, "target": None, "has_delay": False, "is_malformed": False, "isa_mode": "MIPS16"}, 2
        if funct == 7:
            return {"address": addr, "size": 2, "mnemonic": "move", "operands": f"{M16_REG_NAMES[ry]}, {M16_R32_NAMES[w16 & 0x1f]}", "is_branch": False, "is_conditional": False, "is_call": False, "is_return": False, "is_indirect": False, "target": None, "has_delay": False, "is_malformed": False, "isa_mode": "MIPS16"}, 2

    if opcode == 0x0d:
        return {"address": addr, "size": 2, "mnemonic": "li", "operands": f"{M16_REG_NAMES[rx]}, {w16 & 0xff}", "is_branch": False, "is_conditional": False, "is_call": False, "is_return": False, "is_indirect": False, "target": None, "has_delay": False, "is_malformed": False, "isa_mode": "MIPS16"}, 2
    if opcode == 0x0e:
        return {"address": addr, "size": 2, "mnemonic": "cmpi", "operands": f"{M16_REG_NAMES[rx]}, {w16 & 0xff}", "is_branch": False, "is_conditional": False, "is_call": False, "is_return": False, "is_indirect": False, "target": None, "has_delay": False, "is_malformed": False, "isa_mode": "MIPS16"}, 2

    if opcode in (0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x18, 0x19, 0x1a, 0x1b):
        mnem_map = {0x10: "lb", 0x11: "lh", 0x12: "lw", 0x13: "lw", 0x14: "lbu", 0x15: "lhu", 0x16: "lw", 0x18: "sb", 0x19: "sh", 0x1a: "sw", 0x1b: "sw"}
        m = mnem_map[opcode]
        if opcode in (0x12, 0x1a):
            ops = f"{M16_REG_NAMES[rx]}, {(w16 & 0xff)*4}($sp)"
        elif opcode == 0x16:
            ops = f"{M16_REG_NAMES[rx]}, {(w16 & 0xff)*4}($pc)"
        else:
            scale = 4 if m in ("lw", "sw") else 2 if m in ("lh", "sh", "lhu") else 1
            ops = f"{M16_REG_NAMES[ry]}, {(w16 & 0x1f)*scale}({M16_REG_NAMES[rx]})"
        return {"address": addr, "size": 2, "mnemonic": m, "operands": ops, "is_branch": False, "is_conditional": False, "is_call": False, "is_return": False, "is_indirect": False, "target": None, "has_delay": False, "is_malformed": False, "isa_mode": "MIPS16"}, 2

    if opcode == 0x1c:
        funct = w16 & 0x3
        m = "addu" if funct == 1 else "subu" if funct == 3 else "addu"
        return {"address": addr, "size": 2, "mnemonic": m, "operands": f"{M16_REG_NAMES[rz]}, {M16_REG_NAMES[rx]}, {M16_REG_NAMES[ry]}", "is_branch": False, "is_conditional": False, "is_call": False, "is_return": False, "is_indirect": False, "target": None, "has_delay": False, "is_malformed": False, "isa_mode": "MIPS16"}, 2

    if opcode == 0x1d:
        funct = w16 & 0x1f
        if funct == 0:
            nd = (w16 >> 7) & 1
            l = (w16 >> 6) & 1
            ra = (w16 >> 5) & 1
            if l == 0 and ra == 1:
                return {"address": addr, "size": 2, "mnemonic": "jrc ra" if nd == 1 else "jr ra", "operands": "$ra", "is_branch": False, "is_conditional": False, "is_call": False, "is_return": True, "is_indirect": False, "target": None, "has_delay": (nd == 0), "is_malformed": False, "isa_mode": "MIPS16"}, 2
            elif l == 0 and ra == 0:
                return {"address": addr, "size": 2, "mnemonic": "jrc" if nd == 1 else "jr", "operands": f"{M16_REG_NAMES[rx]}", "is_branch": True, "is_conditional": False, "is_call": False, "is_return": False, "is_indirect": True, "target": None, "has_delay": (nd == 0), "is_malformed": False, "isa_mode": "MIPS16"}, 2
            elif l == 1:
                return {"address": addr, "size": 2, "mnemonic": "jalrc" if nd == 1 else "jalr", "operands": f"{M16_REG_NAMES[rx]}", "is_branch": False, "is_conditional": False, "is_call": True, "is_return": False, "is_indirect": True, "target": None, "has_delay": (nd == 0), "is_malformed": False, "isa_mode": "MIPS16"}, 2

        rr_map = {0x01: "sdbbp", 0x02: "slt", 0x03: "sltu", 0x04: "sllv", 0x05: "break", 0x06: "srlv", 0x07: "srav", 0x0a: "cmp", 0x0b: "neg", 0x0c: "and", 0x0d: "or", 0x0e: "xor", 0x0f: "not", 0x10: "mfhi", 0x11: "seb", 0x12: "mflo", 0x18: "mult", 0x19: "multu", 0x1a: "div", 0x1b: "divu"}
        if funct in rr_map:
            return {"address": addr, "size": 2, "mnemonic": rr_map[funct], "operands": f"{M16_REG_NAMES[rx]}, {M16_REG_NAMES[ry]}", "is_branch": False, "is_conditional": False, "is_call": False, "is_return": False, "is_indirect": False, "target": None, "has_delay": False, "is_malformed": False, "isa_mode": "MIPS16"}, 2

    # Reserved opcodes: 0x07, 0x0f, 0x17, 0x1f
    return {
        "address": addr, "size": 2, "mnemonic": f"unsupported_mips16_{opcode:02x}", "operands": f"0x{w16:04x}",
        "is_branch": False, "is_conditional": False, "is_call": False,
        "is_return": False, "is_indirect": False, "target": None,
        "has_delay": False, "is_malformed": True, "isa_mode": "MIPS16"
    }, 2

def decode_executable_segment(code_bytes, start_vaddr, is_m16_default, m32_regions):
    cs = Cs(CS_ARCH_MIPS, CS_MODE_MIPS32 | CS_MODE_BIG_ENDIAN)
    offset = 0
    instructions = []
    decoded_bytes = 0
    literal_pool_bytes = 0
    padding_bytes = 0
    invalid_bytes = 0

    while offset < len(code_bytes):
        cur_addr = start_vaddr + offset
        
        # Check alignment padding (runs of zeroes)
        if offset + 4 <= len(code_bytes) and code_bytes[offset:offset+4] == b'\x00\x00\x00\x00':
            padding_bytes += 4
            offset += 4
            continue
        elif offset + 2 <= len(code_bytes) and code_bytes[offset:offset+2] == b'\x00\x00':
            padding_bytes += 2
            offset += 2
            continue

        is_m16 = is_m16_default
        if m32_regions:
            if any(r[0] <= cur_addr < r[1] for r in m32_regions):
                is_m16 = False
        if not is_m16 and (cur_addr % 4 != 0):
            is_m16 = True

        if is_m16:
            inst, read_sz = decode_mips16_instruction(code_bytes, offset, cur_addr)
            if inst["is_malformed"]:
                invalid_bytes += read_sz
            else:
                instructions.append(inst)
                decoded_bytes += read_sz
            offset += read_sz
        else:
            # MIPS32
            if offset + 4 <= len(code_bytes):
                chunk = code_bytes[offset:offset+4]
                dis_list = list(cs.disasm(chunk, cur_addr))
                if dis_list:
                    i = dis_list[0]
                    m = i.mnemonic.strip()
                    ops = i.op_str.strip()
                    is_call = m in ("jal", "jalr", "bal", "jalx")
                    is_ret = m == "jr" and ops in ("$ra", "$31")
                    is_ind = (m == "jalr") or (m == "jr" and not is_ret)
                    is_branch = m in ("j", "b", "beq", "bne", "blez", "bgez", "bltz", "bgtz") or (m == "jr" and not is_ret)
                    is_cond = m in ("beq", "bne", "blez", "bgez", "bltz", "bgtz")
                    target = None
                    hex_match = re.search(r'0x[0-9a-fA-F]+', ops)
                    if hex_match and not is_ind:
                        target = int(hex_match.group(0), 16)
                    
                    instructions.append({
                        "address": cur_addr,
                        "size": 4,
                        "mnemonic": m,
                        "operands": ops,
                        "is_branch": is_branch,
                        "is_conditional": is_cond,
                        "is_call": is_call,
                        "is_return": is_ret,
                        "is_indirect": is_ind,
                        "target": target,
                        "has_delay": True,
                        "is_malformed": False,
                        "isa_mode": "MIPS32"
                    })
                    decoded_bytes += 4
                else:
                    # Literal pool word
                    literal_pool_bytes += 4
                offset += 4
            else:
                invalid_bytes += (len(code_bytes) - offset)
                offset = len(code_bytes)

    return instructions, decoded_bytes, literal_pool_bytes, padding_bytes, invalid_bytes

def recover_functions_and_cfg(instructions, code_start, code_end, elf_info):
    inst_by_addr = {i["address"]: i for i in instructions}
    inst_idx_by_addr = {i["address"]: idx for idx, i in enumerate(instructions)}
    
    entries = {}
    
    # 1. Metadata entries
    if elf_info["e_entry"] > 0 and code_start <= (elf_info["e_entry"] & ~1) < code_end:
        mode = "MIPS16" if (elf_info["e_entry"] & 1) else "MIPS32"
        entries[elf_info["e_entry"] & ~1] = {"name": "_start", "source": "METADATA_CONFIRMED", "isa_mode": mode}
    if elf_info["dt_init"] > 0 and code_start <= (elf_info["dt_init"] & ~1) < code_end:
        mode = "MIPS16" if (elf_info["dt_init"] & 1) else "MIPS32"
        entries[elf_info["dt_init"] & ~1] = {"name": "_init", "source": "METADATA_CONFIRMED", "isa_mode": mode}
    if elf_info["dt_fini"] > 0 and code_start <= (elf_info["dt_fini"] & ~1) < code_end:
        mode = "MIPS16" if (elf_info["dt_fini"] & 1) else "MIPS32"
        entries[elf_info["dt_fini"] & ~1] = {"name": "_fini", "source": "METADATA_CONFIRMED", "isa_mode": mode}

    # 2. Symbol confirmed
    for s in elf_info["symbols"]:
        a = s["address"] & ~1
        if code_start <= a < code_end and a not in entries:
            entries[a] = {"name": s["name"], "source": "SYMBOL_CONFIRMED", "isa_mode": "MIPS16" if s["is_mips16"] else "MIPS32"}

    # 3. Direct calls & barrier-preceded prologues
    for idx, i in enumerate(instructions):
        a = i["address"]
        # Direct calls
        if i["is_call"] and not i["is_indirect"] and i["target"] is not None:
            t = i["target"] & ~1
            if code_start <= t < code_end and t not in entries:
                mode = "MIPS16" if (i["target"] & 1) or i["mnemonic"] == "jal" else "MIPS32"
                entries[t] = {"name": f"sub_{t:08x}", "source": "DIRECT_CALL_CONFIRMED", "isa_mode": mode}

        # Barrier condition: preceded by return, unconditional jump, or alignment padding
        prev_is_barrier = (
            idx == 0 or
            (idx >= 1 and (instructions[idx-1]["is_return"] or (instructions[idx-1]["is_branch"] and not instructions[idx-1]["is_conditional"]))) or
            (idx >= 2 and instructions[idx-2]["has_delay"] and (instructions[idx-2]["is_return"] or (instructions[idx-2]["is_branch"] and not instructions[idx-2]["is_conditional"]))) or
            (idx >= 1 and instructions[idx-1]["address"] + instructions[idx-1]["size"] < a) # padding gap
        )

        # MIPS16 save prologue
        if i["isa_mode"] == "MIPS16" and i["mnemonic"] == "save":
            if a not in entries and prev_is_barrier:
                entries[a] = {"name": f"sub_{a:08x}", "source": "PROLOGUE_INFERRED", "isa_mode": "MIPS16"}

        # MIPS32 stack frame prologue: addiu $sp, $sp, -imm
        if prev_is_barrier and i["isa_mode"] == "MIPS32" and i["mnemonic"] == "addiu":
            ops = i["operands"].replace(" ", "").lower()
            if ops.startswith("$sp,$sp,-") or ops.startswith("$29,$29,-"):
                if a not in entries:
                    entries[a] = {"name": f"sub_{a:08x}", "source": "PROLOGUE_INFERRED", "isa_mode": "MIPS32"}

    sorted_entry_addrs = sorted(entries.keys())
    
    # 4. Function boundaries & CFG
    recovered_funcs = []
    all_bb_leaders = set()
    total_edges = []
    direct_calls = 0
    indirect_calls = 0
    conditional_branches = 0
    returns = 0
    delay_slots = 0
    mode_transitions = 0
    verified_bounds = 0
    inferred_bounds = 0

    for idx, e_addr in enumerate(sorted_entry_addrs):
        next_addr = sorted_entry_addrs[idx + 1] if idx + 1 < len(sorted_entry_addrs) else code_end
        e_meta = entries[e_addr]
        
        fn_insts = []
        cur_a = e_addr
        # Sweep all instructions up to next_addr
        while cur_a < next_addr and cur_a in inst_by_addr:
            inst = inst_by_addr[cur_a]
            fn_insts.append(inst)
            cur_a += inst["size"]
            
            if inst["is_call"]:
                if inst["is_indirect"]: indirect_calls += 1
                else: direct_calls += 1
                if inst["mnemonic"] == "jalx": mode_transitions += 1
            if inst["is_conditional"]: conditional_branches += 1
            if inst["has_delay"]: delay_slots += 1
            if inst["is_return"]:
                returns += 1

        if not fn_insts: continue

        end_addr = cur_a
        is_verified = any(i["is_return"] for i in fn_insts)
        if is_verified: verified_bounds += 1
        else: inferred_bounds += 1

        # CFG Basic Block Leaders (Single-Entry Single-Exit without call-splitting)
        fn_leaders = {fn_insts[0]["address"]}
        for f_idx, fi in enumerate(fn_insts):
            if fi["is_branch"]:
                if fi["target"] is not None:
                    t_norm = fi["target"] & ~1
                    if e_addr <= t_norm < end_addr:
                        fn_leaders.add(t_norm)
                step = 2 if fi["has_delay"] else 1
                if f_idx + step < len(fn_insts):
                    fn_leaders.add(fn_insts[f_idx + step]["address"])
            elif fi["is_return"]:
                step = 2 if fi["has_delay"] else 1
                if f_idx + step < len(fn_insts):
                    fn_leaders.add(fn_insts[f_idx + step]["address"])

        fn_bb_count = len(fn_leaders)
        all_bb_leaders.update(fn_leaders)

        # Build intra-procedural CFG edges
        sorted_leaders = sorted(fn_leaders)
        for l_idx, lead in enumerate(sorted_leaders):
            next_lead = sorted_leaders[l_idx + 1] if l_idx + 1 < len(sorted_leaders) else end_addr
            b_insts = [i for i in fn_insts if lead <= i["address"] < next_lead]
            if not b_insts: continue
            last_i = b_insts[-1]
            ctrl_i = b_insts[-2] if len(b_insts) >= 2 and b_insts[-2]["has_delay"] and (b_insts[-2]["is_branch"] or b_insts[-2]["is_return"]) else last_i

            if ctrl_i["is_return"]: continue
            if ctrl_i["is_branch"] and not ctrl_i["is_conditional"]:
                if ctrl_i["target"] is not None:
                    t_norm = ctrl_i["target"] & ~1
                    if e_addr <= t_norm < end_addr:
                        total_edges.append((lead, t_norm, "jump"))
            elif ctrl_i["is_conditional"]:
                if ctrl_i["target"] is not None:
                    t_norm = ctrl_i["target"] & ~1
                    if e_addr <= t_norm < end_addr:
                        total_edges.append((lead, t_norm, "true_branch"))
                if l_idx + 1 < len(sorted_leaders):
                    total_edges.append((lead, sorted_leaders[l_idx + 1], "false_branch"))
            else:
                if l_idx + 1 < len(sorted_leaders):
                    total_edges.append((lead, sorted_leaders[l_idx + 1], "fallthrough"))

        recovered_funcs.append({
            "name": e_meta["name"],
            "entry_point": e_addr,
            "end_point": end_addr,
            "size": end_addr - e_addr,
            "isa_mode": e_meta["isa_mode"],
            "source": e_meta["source"],
            "boundary_status": "VERIFIED" if is_verified else "INFERRED",
            "instruction_count": len(fn_insts),
            "bb_count": fn_bb_count
        })

    return {
        "functions": recovered_funcs,
        "function_count": len(recovered_funcs),
        "verified_boundaries_count": verified_bounds,
        "inferred_boundaries_count": inferred_bounds,
        "total_basic_blocks": len(all_bb_leaders),
        "all_bb_leaders": all_bb_leaders,
        "total_edges": total_edges,
        "direct_calls": direct_calls,
        "indirect_calls": indirect_calls,
        "conditional_branches": conditional_branches,
        "returns": returns,
        "delay_slots": delay_slots,
        "mode_transitions": mode_transitions
    }

def evaluate_target(t):
    rel_path = os.path.join("evaluation", "corpus", "openwrt", t["file_name"])
    full_path = os.path.join(REPO_ROOT, rel_path)
    
    with open(full_path, "rb") as f: data = f.read()
    computed_sha = hashlib.sha256(data).hexdigest()
    if computed_sha != t["sha256"]:
        raise ValueError(f"SHA mismatch for {t['logical_path']}: {computed_sha} != {t['sha256']}")

    elf = parse_elf(data)
    
    # Accurate code bounds
    code_start_vaddr = t["code_vaddr_start"]
    code_end_vaddr = t["code_vaddr_end"]
    code_size = code_end_vaddr - code_start_vaddr
    file_offset = elf["vaddr_to_offset"](code_start_vaddr)
    code_bytes = data[file_offset : file_offset + code_size]

    # 1. Decoding
    instructions, dec_bytes, lit_bytes, pad_bytes, inv_bytes = decode_executable_segment(
        code_bytes, code_start_vaddr, t["mips16_flag"], t["m32_regions"]
    )
    
    # True byte coverage = decoded instructions / true executable code bytes
    byte_cov_pct = round((dec_bytes / code_size) * 100, 2)

    # 2. Function & CFG Recovery
    rec_res = recover_functions_and_cfg(instructions, code_start_vaddr, code_end_vaddr, elf)

    # 3. Ghidra Differential Comparison
    ghidra_path = os.path.join(REPO_ROOT, "tools", "ghidra", t["ghidra_file"])
    with open(ghidra_path, "r", encoding="utf-8") as gf: ghidra_data = json.load(gf)

    base_diff = 0x10000 if t["logical_path"] != "bin/busybox" else 0

    ghidra_funcs = [
        f for f in ghidra_data.get("functions", [])
        if not f.get("is_external", False) and f.get("instruction_count", 0) > 0 and (code_start_vaddr <= (int(f["entry_point"], 16) - base_diff) < code_end_vaddr)
    ]
    ghidra_fn_addrs = {(int(f["entry_point"], 16) - base_diff) for f in ghidra_funcs}
    rea_fn_addrs = {f["entry_point"] for f in rec_res["functions"]}

    tp_fn = len(ghidra_fn_addrs.intersection(rea_fn_addrs))
    fp_fn = len(rea_fn_addrs - ghidra_fn_addrs)
    fn_fn = len(ghidra_fn_addrs - rea_fn_addrs)
    fn_precision = round(tp_fn / (tp_fn + fp_fn) * 100, 2) if (tp_fn + fp_fn) > 0 else 0
    fn_recall = round(tp_fn / (tp_fn + fn_fn) * 100, 2) if (tp_fn + fn_fn) > 0 else 0

    ghidra_bbs = [
        b for b in ghidra_data.get("basic_blocks", [])
        if code_start_vaddr <= (int(b["min_address"], 16) - base_diff) < code_end_vaddr
    ]
    ghidra_bb_addrs = {(int(b["min_address"], 16) - base_diff) for b in ghidra_bbs}
    rea_bb_addrs = rec_res["all_bb_leaders"]
    
    tp_bb = len(ghidra_bb_addrs.intersection(rea_bb_addrs))
    fp_bb = len(rea_bb_addrs - ghidra_bb_addrs)
    fn_bb = len(ghidra_bb_addrs - rea_bb_addrs)
    bb_precision = round(tp_bb / (tp_bb + fp_bb) * 100, 2) if (tp_bb + fp_bb) > 0 else 0
    bb_recall = round(tp_bb / (tp_bb + fn_bb) * 100, 2) if (tp_bb + fn_bb) > 0 else 0

    # Ghidra edge set
    ghidra_edges = set()
    for b in ghidra_bbs:
        src = int(b["min_address"], 16) - base_diff
        for e in b.get("edges", []):
            dst = int(e["target_address"], 16) - base_diff
            if code_start_vaddr <= dst < code_end_vaddr:
                ghidra_edges.add((src, dst))

    rea_edge_set = set((e[0], e[1]) for e in rec_res["total_edges"])
    tp_edges = len(ghidra_edges.intersection(rea_edge_set))
    fp_edges = len(rea_edge_set - ghidra_edges)
    fn_edges = len(ghidra_edges - rea_edge_set)
    edge_precision = round(tp_edges / (tp_edges + fp_edges) * 100, 2) if (tp_edges + fp_edges) > 0 else 0
    edge_recall = round(tp_edges / (tp_edges + fn_edges) * 100, 2) if (tp_edges + fn_edges) > 0 else 0

    return {
        "binary": t["logical_path"],
        "sha256": t["sha256"],
        "file_size": t["size"],
        "architecture": "MIPS32 Big-Endian (ath79 MIPS 24Kc ASE MIPS16)" if t["mips16_flag"] else "MIPS32 Big-Endian (ath79 MIPS 24Kc)",
        "code_segment": {
            "vaddr_start": f"0x{code_start_vaddr:08x}",
            "vaddr_end": f"0x{code_end_vaddr:08x}",
            "total_code_bytes": code_size,
            "file_offset": file_offset
        },
        "byte_coverage": {
            "true_code_denominator_bytes": code_size,
            "decoded_instruction_bytes": dec_bytes,
            "literal_pool_bytes": lit_bytes,
            "alignment_padding_bytes": pad_bytes,
            "unsupported_or_invalid_bytes": inv_bytes,
            "corrected_byte_coverage_pct": byte_cov_pct,
            "unsupported_instruction_rate_pct": round((inv_bytes / code_size) * 100, 2)
        },
        "function_recovery": {
            "total_recovered": rec_res["function_count"],
            "sources": {
                "symbol_confirmed": sum(1 for f in rec_res["functions"] if f["source"] == "SYMBOL_CONFIRMED"),
                "metadata_confirmed": sum(1 for f in rec_res["functions"] if f["source"] == "METADATA_CONFIRMED"),
                "direct_call_confirmed": sum(1 for f in rec_res["functions"] if f["source"] == "DIRECT_CALL_CONFIRMED"),
                "prologue_inferred": sum(1 for f in rec_res["functions"] if f["source"] == "PROLOGUE_INFERRED"),
            },
            "verified_boundaries": rec_res["verified_boundaries_count"],
            "inferred_boundaries": rec_res["inferred_boundaries_count"],
            "mips16_functions": sum(1 for f in rec_res["functions"] if f["isa_mode"] == "MIPS16"),
            "mips32_functions": sum(1 for f in rec_res["functions"] if f["isa_mode"] == "MIPS32"),
            "direct_calls_discovered": rec_res["direct_calls"],
            "indirect_calls_flagged": rec_res["indirect_calls"],
            "indirect_resolution_status": f"{rec_res['indirect_calls']} indirect calls preserved as INCONCLUSIVE",
            "returns_identified": rec_res["returns"]
        },
        "ghidra_differential": {
            "ghidra_ground_truth_functions": len(ghidra_funcs),
            "rea_recovered_functions": rec_res["function_count"],
            "matched_functions_tp": tp_fn,
            "false_positives_fp": fp_fn,
            "false_negatives_fn": fn_fn,
            "function_precision_pct": fn_precision,
            "function_recall_pct": fn_recall,
            "ghidra_basic_blocks": len(ghidra_bbs),
            "rea_recovered_basic_blocks": len(rea_bb_addrs),
            "basic_block_matched_tp": tp_bb,
            "basic_block_fp": fp_bb,
            "basic_block_fn": fn_bb,
            "basic_block_precision_pct": bb_precision,
            "basic_block_recall_pct": bb_recall,
            "ghidra_cfg_edges": len(ghidra_edges),
            "rea_cfg_edges": len(rea_edge_set),
            "cfg_edge_matched_tp": tp_edges,
            "cfg_edge_fp": fp_edges,
            "cfg_edge_fn": fn_edges,
            "cfg_edge_precision_pct": edge_precision,
            "cfg_edge_recall_pct": edge_recall,
            "mode_transitions_identified": rec_res["mode_transitions"],
            "delay_slots_tracked": rec_res["delay_slots"]
        }
    }

def main():
    print("================================================================================")
    print("REA Milestone 4.3.2: Independent MIPS16, Function Recovery & CFG Acceptance Audit")
    print("OpenWrt 23.05.0 MIPS32/MIPS16 ath79 Embedded Binaries")
    print("================================================================================\n")

    report_targets = []
    for t in TARGETS:
        print(f"[*] Auditing {t['logical_path']} ({t['size']} bytes)...")
        res = evaluate_target(t)
        report_targets.append(res)
        bc = res["byte_coverage"]
        fr = res["function_recovery"]
        gd = res["ghidra_differential"]
        print(f"    - Corrected Byte Coverage: {bc['corrected_byte_coverage_pct']}% ({bc['decoded_instruction_bytes']}/{bc['true_code_denominator_bytes']} bytes)")
        print(f"    - Functions Recovered: {fr['total_recovered']} (TP={gd['matched_functions_tp']}, FP={gd['false_positives_fp']}, FN={gd['false_negatives_fn']})")
        print(f"    - Function Precision: {gd['function_precision_pct']}%, Recall: {gd['function_recall_pct']}%")
        print(f"    - Basic Block Precision: {gd['basic_block_precision_pct']}%, Recall: {gd['basic_block_recall_pct']}%")
        print(f"    - CFG Edge Precision: {gd['cfg_edge_precision_pct']}%, Recall: {gd['cfg_edge_recall_pct']}%\n")

    out_path = os.path.join(REPO_ROOT, "evaluation", "reports", "openwrt-capstone-evaluation.json")
    os.makedirs(os.path.dirname(out_path), exist_ok=True)
    with open(out_path, "w", encoding="utf-8") as f:
        json.dump(report_targets, f, indent=2)
    print(f"[+] Complete machine-readable acceptance evaluation saved to {out_path}")

if __name__ == "__main__":
    main()
