#!/usr/bin/env node
// S6 A2: assemble a universal (fat) Mach-O from two real thin Mach-O files, as `lipo -create`
// would. The CONTAINER IS FABRICATED by this script, not produced by Apple's lipo (not
// available in this Linux container); the slices are the real darwin binaries of
// scripts/build_cross.sh, copied byte for byte.
// Layout: fat_header {magic 0xcafebabe, nfat_arch} then one fat_arch {cputype, cpusubtype,
// offset, size, align} per slice (big-endian u32), slices aligned on 2^14 (lipo's alignment for
// arm64; x86_64 only needs 2^12). cputype / cpusubtype are copied from each slice's header.
//   node scripts/make_fat.mjs <out> <slice> <slice> [...]
import { readFileSync, writeFileSync } from "node:fs";

const ALIGN_LOG2 = 14;
const ALIGN = 1 << ALIGN_LOG2;
const up = (n) => Math.ceil(n / ALIGN) * ALIGN;

export function makeFat(slices) {
  let pos = ALIGN;
  const placed = slices.map((s) => {
    const magic = s.readUInt32LE(0);
    if (magic !== 0xfeedfacf && magic !== 0xfeedface)
      throw new Error("slice is not a little-endian Mach-O");
    const at = pos;
    pos = up(pos + s.length);
    return at;
  });
  const end = placed.at(-1) + slices.at(-1).length;
  const fat = Buffer.alloc(end);
  fat.writeUInt32BE(0xcafebabe, 0);
  fat.writeUInt32BE(slices.length, 4);
  slices.forEach((s, i) => {
    const at = 8 + i * 20;
    fat.writeUInt32BE(s.readUInt32LE(4), at); // cputype
    fat.writeUInt32BE(s.readUInt32LE(8), at + 4); // cpusubtype
    fat.writeUInt32BE(placed[i], at + 8);
    fat.writeUInt32BE(s.length, at + 12);
    fat.writeUInt32BE(ALIGN_LOG2, at + 16);
    s.copy(fat, placed[i]);
  });
  return fat;
}

if (import.meta.main) {
  const [out, ...inputs] = process.argv.slice(2);
  if (!out || inputs.length < 2) {
    process.stderr.write("usage: make_fat.mjs <out> <slice> <slice> [...]\n");
    process.exit(2);
  }
  writeFileSync(out, makeFat(inputs.map((p) => readFileSync(p))));
}
