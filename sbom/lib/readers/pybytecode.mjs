// Module-level name bindings of a CPython 3.13 code object, from its instruction stream.
//
// Only straight-line patterns of the top-level code are recognized (nested code objects are
// never entered):
//   const        LOAD_CONST k; STORE_NAME n                       n = <constant>
//   chain        LOAD_CONST k; (COPY 1; STORE_NAME a)*; STORE_NAME n    a = b = n = <constant>
//   import-from  LOAD_CONST level; LOAD_CONST fromlist; IMPORT_NAME m; (IMPORT_FROM x; STORE_NAME a)+
//   self         LOAD_NAME n; STORE_NAME n                         n = n (urllib3 does this): ignored,
//                                                                   it rebinds the value n already has
// Every other STORE_NAME is a binding of kind "other". Control flow is not modelled: callers
// must treat several bindings of one name as ambiguous.
//
// Opcode numbers are those of CPython 3.13 (opcode.opmap, 3.13.17). They differ in 3.11, 3.12 and
// 3.14, so callers must check the .pyc magic first (PYC_MAGIC in pyinstaller.mjs).
export const OPCODE = {
  CACHE: 0,
  POP_TOP: 32,
  COPY: 61,
  EXTENDED_ARG: 71,
  IMPORT_FROM: 74,
  IMPORT_NAME: 75,
  LOAD_CONST: 83,
  LOAD_NAME: 92,
  STORE_NAME: 114,
};

/** Wordcode → [{op, arg}] with EXTENDED_ARG folded in and inline cache words dropped. */
export function decodeInstructions(code) {
  const out = [];
  let extended = 0;
  for (let i = 0; i + 1 < code.length; i += 2) {
    const op = code[i];
    const arg = code[i + 1] | extended;
    if (op === OPCODE.CACHE) continue;
    if (op === OPCODE.EXTENDED_ARG) {
      extended = arg << 8;
      continue;
    }
    extended = 0;
    out.push({ op, arg });
  }
  return out;
}

const isConst = (ins) => ins?.op === OPCODE.LOAD_CONST;
const isStore = (ins) => ins?.op === OPCODE.STORE_NAME;
const isCopy1 = (ins) => ins?.op === OPCODE.COPY && ins.arg === 1;

function constBinding(ins, i, consts) {
  // Walk back over (COPY 1 | STORE_NAME)* to the LOAD_CONST, simulating the value stack: the
  // constant is stored by this STORE_NAME only if it was still on the stack at that point.
  let j = i - 1;
  while (isStore(ins[j]) || isCopy1(ins[j])) j -= 1;
  if (!isConst(ins[j])) return null;
  let depth = 1;
  for (let k = j + 1; k < i; k += 1) {
    if (isCopy1(ins[k])) depth += 1;
    else {
      depth -= 1;
      if (depth < 1) return null;
    }
  }
  return { kind: "const", value: consts[ins[j].arg] };
}

function importBinding(ins, i, code) {
  // IMPORT_NAME m; (IMPORT_FROM x; STORE_NAME a)+ — ins[i-1] is the IMPORT_FROM of this store.
  let j = i - 2;
  while (isStore(ins[j]) && ins[j - 1]?.op === OPCODE.IMPORT_FROM) j -= 2;
  if (ins[j]?.op !== OPCODE.IMPORT_NAME) return null;
  if (!isConst(ins[j - 1]) || !isConst(ins[j - 2])) return null;
  const level = code.consts[ins[j - 2].arg];
  const fromlist = code.consts[ins[j - 1].arg];
  if (!Number.isSafeInteger(level) || level < 0 || !Array.isArray(fromlist))
    return null;
  const module = code.names[ins[j].arg];
  const imported = code.names[ins[i - 1].arg];
  if (typeof module !== "string" || typeof imported !== "string") return null;
  return { kind: "import-from", level, module, imported };
}

/** Map name → [binding] for the top-level code object of a module. */
export function moduleBindings(code) {
  const ins = decodeInstructions(code.code);
  const bindings = new Map();
  for (let i = 0; i < ins.length; i += 1) {
    if (!isStore(ins[i])) continue;
    const name = code.names[ins[i].arg];
    if (typeof name !== "string") continue;
    if (ins[i - 1]?.op === OPCODE.LOAD_NAME && ins[i - 1].arg === ins[i].arg)
      continue;
    let binding = null;
    if (ins[i - 1]?.op === OPCODE.IMPORT_FROM)
      binding = importBinding(ins, i, code);
    else binding = constBinding(ins, i, code.consts);
    const list = bindings.get(name) ?? [];
    list.push(binding ?? { kind: "other" });
    bindings.set(name, list);
  }
  return bindings;
}
