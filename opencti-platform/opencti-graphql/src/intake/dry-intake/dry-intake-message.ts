import { Stix2Splitter } from '../../utils/stix2-splitter';
import type { ImportContext } from '../stix-import/context';
import { eventBundle, transformBundle } from '../stix-import/transform';
import { StixImportError, type StixObject } from '../stix-import/types';
import type { DryClient } from './dry-client';

// One push message through the dry intake, up to its rung, as the worker handles it
// (opencti-worker push_handler.py) but without writing anything:
// - ack: nothing, the message is acked (transport ceiling);
// - split: decode the envelope and the bundle, split a multi-object bundle (the worker splits it
//   and publishes the parts again, or, flagged no_split, splits it inside its import; here the
//   parts are only counted);
// - map: decode, then the transformation into GraphQL operations (it splits by itself);
// - validate: map, and the client parses, validates and coerces every operation against the
//   platform schema (see dry-client.ts).
// The objects of a message are those of the bundle received, before any split, at every rung but
// ack (0): the same count whatever the rung, so the rungs compare per object.
// Decoding as the worker (base64.b64decode, a strict UTF-8 decode, json.loads): a content that is
// not a string or not valid UTF-8 is refused. Two differences left, on malformed messages only:
// the native base64 decoder ignores a wrong padding Python refuses (the faithful decoder,
// b64decode in stix-import/utils.ts, would re-encode every content to check it: a cost of the
// harness on the stage it measures), and Python's json.loads reads NaN and Infinity, JSON.parse
// refuses them.
export const DRY_RUNGS = ['ack', 'split', 'map', 'validate'] as const;
export type DryRung = typeof DRY_RUNGS[number];

export interface DryMessageResult {
  // What the worker answers to the broker: nack for a message it cannot handle
  ack: boolean;
  // The stage that failed the message, when it is not acked or the transformation has a defect
  failedStage: 'decode' | 'split' | 'map' | null;
  // A native error of the transformation: a defect of the port, not an outcome pycti can give
  defect: boolean;
  // Objects of the bundle received (the event's object for an event), before any split
  objects: number;
  // Bundles the split gives (split rung, multi-object bundle only)
  parts: number;
  operations: number;
  // Per object outcome of the transformation: transformed, the Python error name, or set_aside
  // for an object the split sets aside (unsupported type, at the split rung too); a duplicate in
  // the bundle has none
  outcomes: Record<string, number>;
  // Seconds spent per stage
  timings: Partial<Record<'decode' | 'split' | 'map', number>>;
}

export interface DryIntakeDeps {
  rung: DryRung;
  client: DryClient;
  // The transformation context of a draft (pycti keeps one for the life of the worker)
  contextFor: (draftId: string) => ImportContext;
}

const seconds = (start: bigint) => Number(process.hrtime.bigint() - start) / 1e9;

export const emptyResult = (): DryMessageResult => ({ ack: true, failedStage: null, defect: false, objects: 0, parts: 0, operations: 0, outcomes: {}, timings: {} });

interface Decoded {
  type: string;
  content: StixObject;
  update: boolean;
  types: string[] | null;
  draftId: string;
}

const UTF8 = new TextDecoder('utf-8', { fatal: true });

const decode = (body: string): Decoded => {
  const data = JSON.parse(body);
  if (typeof data.content !== 'string') {
    throw new TypeError('argument should be a bytes-like object or ASCII string');
  }
  const content = JSON.parse(UTF8.decode(Buffer.from(data.content, 'base64')));
  return {
    // data.get("type", "bundle"): an explicit null is not a bundle, the worker refuses it
    type: Object.prototype.hasOwnProperty.call(data, 'type') ? data.type : 'bundle',
    content,
    update: data.update ?? false,
    types: Array.isArray(data.entities_types) && data.entities_types.length > 0 ? data.entities_types : null,
    draftId: data.draft_id ?? '',
  };
};

// The bundle the worker imports, or an error for a message it refuses
const bundleOf = (decoded: Decoded): { bundle: StixObject; update: boolean } => {
  if (decoded.type === 'bundle') {
    if (!Array.isArray(decoded.content.objects) || decoded.content.objects.length === 0) {
      throw new Error('JSON data type is not a STIX2 bundle');
    }
    return { bundle: decoded.content, update: decoded.update };
  }
  if (decoded.type === 'event') {
    return { bundle: eventBundle(decoded.content), update: true };
  }
  throw new Error(`Unsupported event type ${decoded.type}`);
};

export const processDryMessage = async (body: string, deps: DryIntakeDeps): Promise<DryMessageResult> => {
  const result = emptyResult();
  if (deps.rung === 'ack') {
    return result;
  }
  let start = process.hrtime.bigint();
  let decoded: Decoded;
  let bundle: StixObject;
  let update: boolean;
  try {
    decoded = decode(body);
    ({ bundle, update } = bundleOf(decoded));
  } catch {
    result.timings.decode = seconds(start);
    return { ...result, ack: false, failedStage: 'decode' };
  }
  result.timings.decode = seconds(start);
  result.objects = (bundle.objects as StixObject[]).length;
  start = process.hrtime.bigint();
  if (deps.rung === 'split') {
    try {
      if (decoded.type === 'bundle' && result.objects > 1) {
        const { numberExpectations, incompatibleItems } = new Stix2Splitter().splitBundleWithExpectations(bundle, false, bundle.x_opencti_event_version);
        result.parts = numberExpectations;
        if (incompatibleItems.length > 0) {
          result.outcomes.set_aside = incompatibleItems.length;
        }
      }
    } catch {
      result.ack = false;
      result.failedStage = 'split';
    }
    result.timings.split = seconds(start);
    return result;
  }
  const operationsBefore = deps.client.operations;
  try {
    const { items, incompatible } = await transformBundle(deps.contextFor(decoded.draftId), bundle, update, decoded.types);
    items.forEach(({ outcome }) => {
      result.outcomes[outcome] = (result.outcomes[outcome] ?? 0) + 1;
    });
    if (incompatible.length > 0) {
      result.outcomes.set_aside = incompatible.length;
    }
  } catch (error) {
    // A bundle error (the split failed) fails the message; any other error is a defect of the port,
    // nacked as the worker nacks an unmanaged exception (push_handler.py:271-275)
    result.ack = false;
    result.defect = !(error instanceof StixImportError);
    result.failedStage = 'map';
  }
  result.operations = deps.client.operations - operationsBefore;
  result.timings.map = seconds(start);
  return result;
};
