"""Read files out of PlayStation disc images (.cue, raw 2352-byte .bin, 2048-byte .iso)."""

from __future__ import annotations

import re
import struct
from dataclasses import dataclass
from pathlib import Path

SYNC = b"\x00" + b"\xff" * 10 + b"\x00"


@dataclass
class Entry:
    path: str
    lba: int
    size: int
    is_dir: bool


class Disc:
    def __init__(self, path: str | Path):
        path = Path(path)
        if path.suffix.lower() == ".cue":
            path = self._data_track(path)
        self.path = path
        self.f = open(path, "rb")
        head = self.f.read(16)
        if head[:12] == SYNC:
            self.sector = 2352
            self.offset = 24 if head[15] == 2 else 16
        else:
            self.sector, self.offset = 2048, 0
        pvd = self.read(16)
        if pvd[1:6] != b"CD001":
            raise ValueError(f"{path}: no ISO9660 volume descriptor")
        self.root = pvd[156:156 + 34]

    @staticmethod
    def _data_track(cue: Path) -> Path:
        text = cue.read_text(errors="replace")
        m = re.search(r'FILE\s+"([^"]+)"', text)
        if not m:
            raise ValueError(f"{cue}: no FILE line")
        return cue.parent / m.group(1)

    def read(self, lba: int, count: int = 1) -> bytes:
        out = bytearray()
        for i in range(count):
            self.f.seek((lba + i) * self.sector + self.offset)
            out += self.f.read(2048)
        return bytes(out)

    def _records(self, lba: int, size: int):
        data = self.read(lba, (size + 2047) // 2048)
        pos = 0
        while pos < len(data):
            n = data[pos]
            if n == 0:  # records never cross a sector; skip to the next one
                pos = (pos // 2048 + 1) * 2048
                continue
            rec = data[pos:pos + n]
            pos += n
            name_len = rec[32]
            name = rec[33:33 + name_len]
            if name in (b"\x00", b"\x01"):
                continue
            yield (name.decode("ascii", "replace").split(";")[0],
                   struct.unpack_from("<I", rec, 2)[0],
                   struct.unpack_from("<I", rec, 10)[0],
                   bool(rec[25] & 2))

    def walk(self):
        stack = [("", struct.unpack_from("<I", self.root, 2)[0], struct.unpack_from("<I", self.root, 10)[0])]
        while stack:
            prefix, lba, size = stack.pop()
            for name, elba, esize, is_dir in self._records(lba, size):
                p = f"{prefix}/{name}" if prefix else name
                yield Entry(p, elba, esize, is_dir)
                if is_dir:
                    stack.append((p, elba, esize))

    def find(self, name: str) -> Entry:
        want = name.upper().split(";")[0].lstrip("\\/").replace("\\", "/")
        for e in self.walk():
            if e.path.upper() == want:
                return e
        raise FileNotFoundError(name)

    def read_file(self, name: str) -> bytes:
        e = self.find(name)
        return self.read(e.lba, (e.size + 2047) // 2048)[:e.size]

    def boot_exe(self) -> str:
        cnf = self.read_file("SYSTEM.CNF").decode("ascii", "replace")
        m = re.search(r"BOOT2?\s*=\s*cdrom0?:\\?([^;\s]+)", cnf, re.I)  # PS1 BOOT, PS2 BOOT2
        if not m:
            raise ValueError("SYSTEM.CNF has no BOOT line")
        return m.group(1).replace("\\", "/")


@dataclass
class PsxExe:
    pc0: int
    gp0: int
    t_addr: int
    t_size: int
    b_addr: int
    b_size: int
    region: str

    @classmethod
    def parse(cls, data: bytes) -> "PsxExe":
        if data[:8] != b"PS-X EXE":
            raise ValueError("not a PS-X EXE")
        pc0, gp0, t_addr, t_size = struct.unpack_from("<4I", data, 0x10)
        b_addr, b_size = struct.unpack_from("<2I", data, 0x28)
        region = data[0x4C:0x800].split(b"\x00")[0].decode("ascii", "replace")
        return cls(pc0, gp0, t_addr, t_size, b_addr, b_size, region)
