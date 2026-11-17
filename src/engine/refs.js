import { isObj } from './util.js';

/**
 * Lazily resolves internal JSON-pointer `$ref`s within one OpenAPI document.
 * Never copies the whole tree (so cyclic schemas are fine) and reports refs it
 * cannot follow (external files, typos) instead of throwing.
 */
export function makeResolver(root) {
  const unresolved = new Set();

  function pointer(ref) {
    if (typeof ref !== 'string' || !ref.startsWith('#')) return undefined;
    if (ref === '#') return root;
    const parts = ref
      .slice(2)
      .split('/')
      .map((p) => decodeURIComponent(p).replace(/~1/g, '/').replace(/~0/g, '~'));
    let cur = root;
    for (const p of parts) {
      if (cur === null || typeof cur !== 'object' || !(p in cur)) return undefined;
      cur = cur[p];
    }
    return cur;
  }

  /** Follow a chain of `$ref`s. OAS 3.1 sibling keywords are layered on top. */
  function deref(node) {
    let ref = null;
    const seen = new Set();
    while (isObj(node) && typeof node.$ref === 'string') {
      if (seen.has(node.$ref)) return { node: {}, ref, circular: true };
      seen.add(node.$ref);
      ref = node.$ref;
      const target = pointer(node.$ref);
      if (target === undefined) {
        unresolved.add(node.$ref);
        return { node: {}, ref, unresolved: true };
      }
      const { $ref, ...siblings } = node;
      node = Object.keys(siblings).length && isObj(target) ? { ...target, ...siblings } : target;
    }
    return { node, ref };
  }

  return { deref, pointer, unresolved, root };
}

/** Name of the component a ref points at, e.g. `#/components/schemas/Address` -> `Address`. */
export const refName = (ref) => (typeof ref === 'string' ? decodeURIComponent(ref.split('/').pop()) : null);
