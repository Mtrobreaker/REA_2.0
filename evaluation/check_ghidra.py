import struct

with open('evaluation/corpus/openwrt/bin_busybox', 'rb') as f:
    buf = f.read()

# file offset of 0x403dc0:
start_off = 15104 + (0x403dc0 - 0x403b00)
for i in range(0, 32, 2):
    w16 = struct.unpack('>H', buf[start_off + i : start_off + i + 2])[0]
    print(f"  {hex(0x403dc0 + i)}: {hex(w16)}")
