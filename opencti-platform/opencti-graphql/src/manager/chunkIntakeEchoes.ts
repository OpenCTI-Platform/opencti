// Chunk-queue intake: echo ids. The worker's capture transport answers an id-less create
// (label, external reference, kill chain phase, an author by name) with an `echo--` id and
// ships that create as the PRODUCER of the chunks that reference it; the manager runs the
// producers first and substitutes the real ids. An echo id that reaches a reference check
// unresolved has no producer in its chunk (A9: it leaked from another capture window through
// the client cache) or a producer that failed: nothing can ever resolve it, so retaining
// the operation on it would keep it in the pending store until expiry (B12).
export const ECHO_ID_PREFIX = 'echo--';

export const isEchoId = (id: unknown): boolean => typeof id === 'string' && id.startsWith(ECHO_ID_PREFIX);

// Split a missing-reference list into the ids a later landing can resolve and the echo ids
// nothing can.
export const splitEchoIds = (ids: string[]): { resolvable: string[]; echoes: string[] } => ({
  resolvable: ids.filter((id) => !isEchoId(id)),
  echoes: ids.filter((id) => isEchoId(id)),
});
