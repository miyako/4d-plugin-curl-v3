"""Read-only, bounded object inspection for reviewed native archive identities.

Only regular ar, little-endian Mach-O 64 relocatables and AMD64 COFF objects
are supported. This is not a linker, an executable probe, or a general ABI audit.
Offsets are relative to the thin archive/member, never a universal-file offset.
"""

import struct


def region(data, offset, size):
    if offset < 0 or size < 0 or offset + size > len(data):
        raise ValueError("Object evidence extends beyond its containing bytes")
    return data[offset:offset + size]


def unpack(fmt, data, offset):
    return struct.unpack(fmt, region(data, offset, struct.calcsize(fmt)))


def cstring(data, offset):
    if offset < 0 or offset >= len(data) or b"\0" not in data[offset:]:
        raise ValueError("Unterminated object evidence string")
    return data[offset:data.index(b"\0", offset)].decode("ascii")


def members(data):
    if not data.startswith(b"!<arch>\n"):
        raise ValueError("Expected regular ar for object evidence")
    offset, names = 8, b""
    while offset < len(data):
        header = region(data, offset, 60)
        if header[58:] != b"`\n":
            raise ValueError("Invalid ar member header")
        name = header[:16].decode("ascii").strip()
        size = int(header[48:58])
        start = offset + 60
        payload = region(data, start, size)
        if name.startswith("#1/"):
            length = int(name[3:])
            name = region(payload, 0, length).rstrip(b"\0").decode("ascii")
            start += length
            payload = payload[length:]
        elif name == "//":
            names = payload
        elif name.startswith("/") and name[1:].isdigit():
            index = int(name[1:])
            tail = region(names, index, len(names) - index)
            end = tail.find(b"\0")
            if end < 0:
                end = tail.find(b"/\n")
            if end < 0:
                raise ValueError("Invalid ar long member name")
            name = tail[:end].decode("ascii")
        elif name not in ("/", "//"):
            name = name.rstrip("/")
        if name not in ("/", "//") and not name.startswith("__.SYMDEF"):
            yield name, start, payload
        offset += 60 + size + size % 2


class Object:
    def __init__(self, data):
        self.data = data
        self.sections = []
        self.symbols = {}
        self.symbol_indices = {}
        self.ambiguous_symbols = set()
        if data[:4] == b"\xcf\xfa\xed\xfe":
            self.format = "mach-o-64"
            self._mach()
        elif data[:2] == b"\x64\x86":
            self.format = "coff-amd64"
            self._coff()
        else:
            raise ValueError("Unsupported reviewed object format")

    def _add_symbol(self, index, name, section, value, defined):
        symbol = {"name": name, "section": section, "value": value, "defined": defined}
        self.symbol_indices[index] = symbol
        if defined:
            if name in self.symbols:
                self.ambiguous_symbols.add(name)
            self.symbols[name] = symbol

    def _mach(self):
        _, cpu, _, kind, count, size, _, _ = unpack("<8I", self.data, 0)
        if cpu not in (0x01000007, 0x0100000C) or kind != 1:
            raise ValueError("Unsupported Mach-O reviewed object")
        region(self.data, 32, size)
        offset, symtab = 32, None
        for _ in range(count):
            cmd, length = unpack("<II", self.data, offset)
            if length < 8:
                raise ValueError("Invalid Mach-O load command")
            region(self.data, offset, length)
            if cmd == 0x19:
                nsects = unpack("<I", self.data, offset + 64)[0]
                for index in range(nsects):
                    pos = offset + 72 + 80 * index
                    name = region(self.data, pos, 16).rstrip(b"\0").decode("ascii")
                    addr, length_, raw, _, reloc, nreloc, flags = unpack(
                        "<QQIIIII", self.data, pos + 32)
                    self.sections.append({"name": name, "address": addr, "size": length_,
                                          "offset": raw, "reloc": reloc, "nreloc": nreloc,
                                          "flags": flags})
            elif cmd == 2:
                symtab = unpack("<4I", self.data, offset + 8)
            offset += length
        if symtab is None:
            raise ValueError("Missing Mach-O symbol evidence")
        raw, count, strings, length = symtab
        names = region(self.data, strings, length)
        for index in range(count):
            string, type_, section, _, value = unpack("<IBBHQ", self.data, raw + 16 * index)
            if type_ & 0xE0:
                continue
            self._add_symbol(index, cstring(names, string), section, value,
                             type_ & 0x0E == 0x0E and section > 0)

    def _coff(self):
        _, count, _, raw, nsyms, optional, _ = unpack("<HHIIIHH", self.data, 0)
        if optional:
            raise ValueError("Expected relocatable COFF evidence")
        strings = raw + 18 * nsyms
        names = region(self.data, strings, unpack("<I", self.data, strings)[0])
        for index in range(count):
            pos = 20 + 40 * index
            name = region(self.data, pos, 8).rstrip(b"\0").decode("ascii")
            size, start, reloc, _, nreloc, _, flags = unpack("<IIIIHHI", self.data, pos + 16)
            self.sections.append({"name": name, "address": 0, "size": size,
                                  "offset": start, "reloc": reloc, "nreloc": nreloc,
                                  "flags": flags})
        index = 0
        while index < nsyms:
            pos = raw + 18 * index
            name = region(self.data, pos, 8)
            if name[:4] == b"\0" * 4:
                name = cstring(names, unpack("<I", name, 4)[0])
            else:
                name = name.rstrip(b"\0").decode("ascii")
            value, section, _, storage, aux = unpack("<IhHBB", self.data, pos + 8)
            # Section symbols can repeat (e.g. .rdata COMDAT); keep their indices
            # for relocations, but not in the named definition lookup.
            if storage == 3 and aux:
                self.symbol_indices[index] = {"name": name, "section": section,
                                              "value": value, "defined": section > 0}
            else:
                self._add_symbol(index, name, section, value, section > 0)
            index += 1 + aux

    def location(self, symbol):
        section = self.sections[symbol["section"] - 1]
        relative = symbol["value"] - section["address"]
        if not symbol["defined"] or relative < 0 or relative >= section["size"]:
            raise ValueError("Symbol has no backed section data")
        return section, relative, section["offset"] + relative

    def definition(self, name):
        if name in self.ambiguous_symbols:
            raise ValueError(f"Ambiguous defined object symbol: {name}")
        symbol = self.symbols[name]
        section, _, offset = self.location(symbol)
        return {"symbol": name, "section": section["name"], "objectOffset": offset}

    def value(self, name, size):
        self.definition(name)
        section, relative, offset = self.location(self.symbols[name])
        if relative + size > section["size"]:
            raise ValueError("Version data exceeds its object section")
        return offset, region(self.data, offset, size)

    def pointed_string(self, name, field):
        """Resolve an absolute 64-bit data relocation, not a nearby string."""
        self.definition(name)
        section, relative, offset = self.location(self.symbols[name])
        address = relative + field
        if address + 8 > section["size"]:
            raise ValueError("Version string pointer exceeds section")
        matches = []
        for index in range(section["nreloc"]):
            pos = section["reloc"] + index * (8 if self.format == "mach-o-64" else 10)
            if self.format == "mach-o-64":
                at, info = unpack("<II", self.data, pos)
                if at != address:
                    continue
                if (info >> 24) & 1 or (info >> 25) & 3 != 3 or info >> 28 != 0:
                    raise ValueError("Unsupported Mach-O version pointer relocation")
                external, target = (info >> 27) & 1, info & 0xFFFFFF
                pointer = unpack("<Q", self.data, offset + field)[0]
                if external:
                    symbol = self.symbol_indices[target]
                    target_section, _, target_offset = self.location(symbol)
                    target_offset += pointer
                else:
                    target_section = self.sections[target - 1]
                    target_offset = target_section["offset"] + pointer - target_section["address"]
            else:
                at, target, type_ = unpack("<IIH", self.data, pos)
                if at != address:
                    continue
                if type_ != 1:
                    raise ValueError("Unsupported COFF version pointer relocation")
                target_section, _, target_offset = self.location(self.symbol_indices[target])
                target_offset += unpack("<Q", self.data, offset + field)[0]
            remaining = target_section["offset"] + target_section["size"] - target_offset
            value = cstring(region(self.data, target_offset, remaining), 0)
            matches.append((target_offset, value))
        if len(matches) != 1:
            raise ValueError("Expected one version string relocation")
        return matches[0]
