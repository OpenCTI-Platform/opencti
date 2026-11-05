import { type CaptureWindow, ECHO_PREFIX } from './capture-client';

// The transformation cache as one captured message sees it (the worker's ChunkCapture
// _get_in_cache / _set_in_cache / _purge_echo_cache). The cache is shared by every message of a
// draft, and an echo is only resolvable in the message that created it: for another message it
// is absent, the transformation creates its sub-object again (an idempotent upsert) with a
// producer of its own. Given as the `cache` of the message's transformation context, so the
// transformation itself (stix-import) is unchanged.

const isEcho = (value: unknown): value is { id: string } => value !== null && typeof value === 'object'
  && typeof (value as { id?: unknown }).id === 'string' && (value as { id: string }).id.startsWith(ECHO_PREFIX);

export class CaptureCache extends Map<string, any> {
  constructor(private readonly shared: Map<string, any>, private readonly window: CaptureWindow) {
    super();
  }

  private isForeign(value: unknown) {
    return isEcho(value) && !this.window.echoes.has(value.id);
  }

  has(key: string) {
    return this.shared.has(key) && !this.isForeign(this.shared.get(key));
  }

  get(key: string) {
    const value = this.shared.get(key);
    return this.isForeign(value) ? undefined : value;
  }

  set(key: string, value: any) {
    this.shared.set(key, value);
    if (isEcho(value)) {
      this.window.keys.add(key);
    }
    return this;
  }

  delete(key: string) {
    return this.shared.delete(key);
  }

  get size() {
    return this.shared.size;
  }

  keys() {
    return this.shared.keys();
  }
}

// The end of a captured message: drop the echoes it stored, unless another message replaced them
// since. The worker forgets the draft suffix of the keys (chunk_transport.py _purge_echo_cache),
// so it purges nothing in a draft; the keys here carry it.
export const purgeCaptureWindow = (shared: Map<string, any>, window: CaptureWindow) => {
  window.keys.forEach((key) => {
    const value = shared.get(key);
    if (isEcho(value) && window.echoes.has(value.id)) {
      shared.delete(key);
    }
  });
};
