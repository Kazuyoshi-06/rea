"""Build a synthetic PyInstaller-style onefile file for reader tests (stdlib only).

Layout mirrors what PyInstaller 6.x writes and what lib/readers/pyinstaller.mjs documents:
bootloader stand-in | CArchive (entries, TOC) | 88-byte cookie | optional trailing bytes.
Reads a JSON spec on stdin:
  output        path to write
  prefix        text placed before the archive (it also embeds the cookie magic, like a real
                bootloader does)
  pyvers        python version integer for the cookie (default 313)
  pyc_magic     override of the 4 PYZ magic bytes (hex); default importlib.util.MAGIC_NUMBER
  entries       [{name, type, text|b64, compress}]       plain CArchive entries
  modules       [{name, source, ispkg}]                  compiled into the PYZ entry "PYZ-00.pyz"
  trailing_b64  bytes appended after the cookie
"""
import base64, importlib.util, json, marshal, struct, sys, zlib

MAGIC = b"MEI\014\013\012\013\016"
spec = json.load(sys.stdin)


def entry_bytes(entry):
    if "b64" in entry:
        return base64.b64decode(entry["b64"])
    return entry["text"].encode("utf-8")


archive = bytearray()
toc_entries = []


def add(name, typ, data, compress):
    raw = zlib.compress(data) if compress else data
    toc_entries.append((len(archive), len(raw), len(data), 1 if compress else 0, typ, name))
    archive.extend(raw)


for entry in spec.get("entries", []):
    add(entry["name"], entry["type"], entry_bytes(entry), entry.get("compress", True))

if spec.get("modules") is not None:
    pyz = bytearray(b"PYZ\0")
    pyz += bytes.fromhex(spec["pyc_magic"]) if "pyc_magic" in spec else importlib.util.MAGIC_NUMBER
    pyz += b"\0\0\0\0"  # TOC position, patched below
    toc = []
    for module in spec["modules"]:
        code = compile(module["source"], module["name"], "exec", dont_inherit=True)
        blob = zlib.compress(marshal.dumps(code))
        toc.append((module["name"], (1 if module.get("ispkg") else 0, len(pyz), len(blob))))
        pyz += blob
    toc_position = len(pyz)
    pyz += marshal.dumps(toc)
    pyz[8:12] = struct.pack(">I", toc_position)
    add("PYZ-00.pyz", "z", bytes(pyz), False)

toc_bytes = bytearray()
for offset, clen, ulen, flag, typ, name in toc_entries:
    name_bytes = name.encode("utf-8") + b"\0"
    length = 18 + len(name_bytes)
    length += (-length) % 16
    toc_bytes += struct.pack(">iIIIBc", length, offset, clen, ulen, flag, typ.encode())
    toc_bytes += name_bytes.ljust(length - 18, b"\0")

toc_offset = len(archive)
package_length = len(archive) + len(toc_bytes) + 88
cookie = struct.pack(
    ">8sIIIi64s", MAGIC, package_length, toc_offset, len(toc_bytes),
    spec.get("pyvers", 313), b"libpython3.13.so",
)
prefix = spec.get("prefix", "BOOTLOADER").encode() + MAGIC + b"\0" * 32
data = bytes(prefix) + bytes(archive) + bytes(toc_bytes) + cookie
data += base64.b64decode(spec.get("trailing_b64", ""))
with open(spec["output"], "wb") as handle:
    handle.write(data)
