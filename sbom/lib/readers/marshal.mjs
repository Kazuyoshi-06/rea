// Minimal reader for Python's marshal format (version 4, as written by CPython 3.13), enough to
// read the PYZ table of contents and the constants of module code objects. Pure Node.
//
// Values: None → null, bool → boolean, int → number (BigInt beyond 2^53), float → number,
// str → string, bytes → Buffer, tuple / list → array, dict → Map, set / frozenset → Set,
// code → {kind: "code", ...fields}. References (FLAG_REF / TYPE_REF) follow marshal.c: a slot is
// reserved when a container or code object starts, filled when it ends.
//
// Code object field order is that of CPython 3.11–3.13 (r_object for TYPE_CODE); callers must
// check the .pyc magic number first (see PYC_MAGIC in pyinstaller.mjs). Anything unexpected throws
// MarshalError, which callers turn into a Result.
export class MarshalError extends Error {}

const FLAG_REF = 0x80;
const MAX_DEPTH = 512; // resource guard (CPython allows 2000); module code nests far less

export function readMarshal(buffer, start = 0) {
  const refs = [];
  let pos = start;

  const need = (count) => {
    if (count < 0 || pos + count > buffer.length)
      throw new MarshalError(`truncated data at offset ${pos}`);
  };
  const u8 = () => {
    need(1);
    return buffer[pos++];
  };
  const i32 = () => {
    need(4);
    const value = buffer.readInt32LE(pos);
    pos += 4;
    return value;
  };
  const u32 = () => {
    need(4);
    const value = buffer.readUInt32LE(pos);
    pos += 4;
    return value;
  };
  // Every element takes at least one byte: reject counts the input cannot hold.
  const count = (n) => {
    if (n > buffer.length - pos)
      throw new MarshalError(
        `count ${n} exceeds remaining data at offset ${pos}`,
      );
    return n;
  };
  const text = (length, encoding) => {
    need(length);
    const value = buffer.toString(encoding, pos, pos + length);
    pos += length;
    return value;
  };

  function integer() {
    const size = i32();
    const digits = Math.abs(size);
    need(digits * 2);
    let value = 0n;
    for (let i = 0; i < digits; i += 1) {
      const digit = buffer.readUInt16LE(pos + i * 2);
      if (digit > 0x7fff) throw new MarshalError("invalid long digit");
      value |= BigInt(digit) << BigInt(15 * i);
    }
    pos += digits * 2;
    if (size < 0) value = -value;
    return Number.isSafeInteger(Number(value)) ? Number(value) : value;
  }

  function object(depth) {
    if (depth > MAX_DEPTH) throw new MarshalError("nesting too deep");
    const code = u8();
    const flagged = (code & FLAG_REF) !== 0;
    const type = String.fromCharCode(code & ~FLAG_REF);
    const reserve = () => {
      if (!flagged) return -1;
      refs.push(undefined);
      return refs.length - 1;
    };
    const finish = (slot, value) => {
      if (slot >= 0) refs[slot] = value;
      return value;
    };
    const atom = (value) => {
      if (flagged) refs.push(value);
      return value;
    };
    switch (type) {
      case "0":
        throw new MarshalError("unexpected NULL object");
      case "N":
        return atom(null);
      case "F":
        return atom(false);
      case "T":
        return atom(true);
      case ".":
        return atom({ kind: "ellipsis" });
      case "S":
        return atom({ kind: "stopiteration" });
      case "i":
        return atom(i32());
      case "l":
        return atom(integer());
      case "g": {
        need(8);
        const value = buffer.readDoubleLE(pos);
        pos += 8;
        return atom(value);
      }
      case "y": {
        need(16);
        const value = {
          kind: "complex",
          real: buffer.readDoubleLE(pos),
          imag: buffer.readDoubleLE(pos + 8),
        };
        pos += 16;
        return atom(value);
      }
      case "f": {
        const length = u8();
        return atom(Number(text(length, "latin1")));
      }
      case "x": {
        const real = u8();
        const realText = text(real, "latin1");
        const imag = u8();
        const imagText = text(imag, "latin1");
        return atom({
          kind: "complex",
          real: Number(realText),
          imag: Number(imagText),
        });
      }
      case "s": {
        const length = u32();
        need(length);
        const value = Buffer.from(buffer.subarray(pos, pos + length));
        pos += length;
        return atom(value);
      }
      case "u":
      case "t":
        return atom(text(u32(), "utf8"));
      case "a":
      case "A":
        return atom(text(u32(), "latin1"));
      case "z":
      case "Z":
        return atom(text(u8(), "latin1"));
      case "(":
      case ")":
      case "[": {
        const slot = reserve();
        const n = count(type === ")" ? u8() : u32());
        const items = [];
        for (let i = 0; i < n; i += 1) items.push(object(depth + 1));
        return finish(slot, items);
      }
      case "<":
      case ">": {
        const slot = reserve();
        const n = count(u32());
        const items = new Set();
        for (let i = 0; i < n; i += 1) items.add(object(depth + 1));
        return finish(slot, items);
      }
      case "{": {
        const slot = reserve();
        const map = new Map();
        for (;;) {
          need(1);
          if (buffer[pos] === 0x30) {
            pos += 1; // TYPE_NULL ends the dict
            break;
          }
          const key = object(depth + 1);
          map.set(key, object(depth + 1));
        }
        return finish(slot, map);
      }
      case "r": {
        const index = u32();
        if (index >= refs.length || refs[index] === undefined)
          throw new MarshalError(`invalid reference ${index}`);
        return refs[index];
      }
      case "c": {
        const slot = reserve();
        const field = () => object(depth + 1);
        const value = {
          kind: "code",
          argcount: i32(),
          posonlyargcount: i32(),
          kwonlyargcount: i32(),
          stacksize: i32(),
          flags: i32(),
          code: field(),
          consts: field(),
          names: field(),
          localsplusnames: field(),
          localspluskinds: field(),
          filename: field(),
          name: field(),
          qualname: field(),
          firstlineno: i32(),
          linetable: field(),
          exceptiontable: field(),
        };
        if (!Buffer.isBuffer(value.code) || !Array.isArray(value.consts))
          throw new MarshalError("malformed code object");
        if (!Array.isArray(value.names))
          throw new MarshalError("malformed code object names");
        return finish(slot, value);
      }
      default:
        throw new MarshalError(
          `unsupported marshal type ${JSON.stringify(type)} at offset ${pos - 1}`,
        );
    }
  }

  const value = object(0);
  return { value, end: pos };
}
