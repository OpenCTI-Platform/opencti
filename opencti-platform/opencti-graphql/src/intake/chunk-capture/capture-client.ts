import { randomUUID } from 'node:crypto';
import type { ChunkOperation } from '../../graphql/chunk-executor';
import { type ImportClient, UploadFile } from '../stix-import/types';

// The capture transport of the worker-less intake (POC): the platform-side twin of the worker's
// opencti-worker/src/chunk_transport.py (ChunkCapture). The transformation's mutations are
// recorded instead of executed and answered with an echo; its reads go to `reads`. The recorded
// operations become the chunks the chunk intake manager executes (processChunkMessage), so they
// must be the worker's chunks exactly: opencti-worker/tests/chunk_capture_goldens.py records
// them, tests/01-unit/chunk-capture compares.

export const ECHO_PREFIX = 'echo--';
// Scalar input fields the transformation may read back from a create answer (vocabularies:
// name, category; labels: value; kill chain phases; external references). Never relationship
// fields (createdBy, objectMarking...): the transformation reads objects there, not ids.
const ECHO_SCALAR_FIELDS = ['name', 'value', 'category', 'description', 'kill_chain_name', 'phase_name', 'x_opencti_order', 'source_name', 'url', 'external_id', 'color'];

// The echoes one message created and the cache keys it stored them under: an echo is only
// resolvable inside its own message (its producer travels in this message's chunks), so another
// message reading it from the shared cache is a miss, and the message drops them at its end
// (capture-cache.ts)
export interface CaptureWindow {
  readonly echoes: Set<string>;
  readonly keys: Set<string>;
}

const isPlainObject = (value: unknown): value is Record<string, any> => value !== null && typeof value === 'object' && !Array.isArray(value);

// A snapshot of the variables as the worker publishes them (its NOT_PROVIDED values dropped, an
// undefined here): the transformation may change the objects it passed after the call. A file
// stays an UploadFile: in process it needs no serialization (the worker, sending chunks through a
// queue, imported a bundle with files over HTTP instead), the executor makes it an Upload.
const snapshot = (value: unknown): unknown => {
  if (value instanceof UploadFile) {
    return value;
  }
  if (Array.isArray(value)) {
    return value.map(snapshot);
  }
  if (isPlainObject(value)) {
    return Object.fromEntries(Object.entries(value).filter(([, item]) => item !== undefined).map(([key, item]) => [key, snapshot(item)]));
  }
  return value;
};

// The answer to any root field: _EchoData answers the echo whatever the key
const echoData = (echo: Record<string, unknown>) => new Proxy({}, { get: (_target, key) => (typeof key === 'string' ? echo : undefined) });

export class ChunkCaptureClient implements ImportClient {
  readonly operations: ChunkOperation[] = [];

  readonly window: CaptureWindow = { echoes: new Set(), keys: new Set() };

  constructor(private readonly reads: ImportClient, private readonly newEchoId: () => string = () => `${ECHO_PREFIX}${randomUUID()}`) {}

  async query(document: string, variables: Record<string, unknown> = {}) {
    if (!document.trimStart().startsWith('mutation')) {
      return this.reads.query(document, variables);
    }
    const captured = snapshot(variables) as Record<string, any>;
    // Most creates nest their fields under `input`, observables give them at the top level
    const payload = isPlainObject(captured.input) ? captured.input : captured;
    const stixId = payload.stix_id || captured.stix_id;
    // A create without a STIX id is a sub-object created beforehand (label, external
    // reference, kill chain phase): the transformation sends the id answered inside the owning
    // object's input. It gets a unique echo id and its operation is the PRODUCER of that id: the
    // manager executes producers first and substitutes the real ids.
    const echoId = stixId ? null : this.newEchoId();
    const operation: ChunkOperation = { query: document.split(/\s+/).filter((part) => part.length > 0).join(' '), variables: captured, object_id: stixId ?? null };
    if (echoId) {
      this.window.echoes.add(echoId);
      operation.echo_id = echoId;
    }
    this.operations.push(operation);
    const scalars = Object.fromEntries(ECHO_SCALAR_FIELDS.filter((field) => ['string', 'number', 'boolean'].includes(typeof payload[field])).map((field) => [field, payload[field]]));
    const answerId = stixId || echoId;
    return echoData({
      ...scalars,
      id: answerId,
      standard_id: answerId,
      entity_type: Object.prototype.hasOwnProperty.call(payload, 'type') ? payload.type : 'Unknown',
      parent_types: [],
      observables: [],
    });
  }
}
