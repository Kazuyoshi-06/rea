// Tagged Result for expected failures at untrusted boundaries (artifact bytes, external tool output).
export const ok = (value) => ({ ok: true, value });
export const err = (tag, message, details = undefined) => ({
  ok: false,
  error: details === undefined ? { tag, message } : { tag, message, details },
});
