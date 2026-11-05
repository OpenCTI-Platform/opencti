import { Stix2Splitter } from '../../utils/stix2-splitter';
import type { ImportContext } from './context';
import { importItem } from './importer';
import { ImportClientError, type ImportLogger, type PythonErrorName, StixImportError, type StixObject } from './types';
import { dictGet, iterate, required, setItem } from './utils';

// The transformation of a message: the split, then each object to its operations, in the
// order of the split (pycti import_bundle without its retries, work reports and size limits).
// To know when wiring it in a runtime:
// - it mutates the input objects, as pycti does (extension fields copied to the top level...);
// - a context holds pycti's caches: one context per draft and per bounded batch of messages;
// - the rule apply and rule rescan operations ask until the platform answers complete, as pycti,
//   but within a bound (operations-knowledge.ts);
// - transformBundle does not yield to the event loop between objects: add it when wiring.

// The per-object outcome: the name of the Python error pycti raises. A GraphQL error is pycti's
// ValueError (raised by its query). Any other error is a defect of the port: it is not an
// outcome pycti can give, so it fails the whole transformation.
const pythonOutcome = (error: unknown) => {
  if (error instanceof ImportClientError) {
    return 'ValueError';
  }
  if (error instanceof StixImportError) {
    return error.name;
  }
  throw error;
};

const withObjectId = (logger: ImportLogger, id: unknown): ImportLogger => ({
  error: (message, meta) => logger.error(message, { id, ...meta }),
  warn: (message, meta) => logger.warn(message, { id, ...meta }),
});

export interface TransformResult {
  items: { id: string; outcome: string }[];
  incompatible: string[];
}

// The split, by the platform splitter (shared with the publish path, not a port of pycti's).
// The one place where an error of the platform code ends the whole bundle: pycti's splitter fails
// the same way on the malformed messages it cannot split, so its failure becomes a StixImportError
// carrying the splitter error's name (the bundle error). Where both splitters disagree on a
// malformed message, the difference is declared in accepted-differences.json.
const splitBundle = (bundle: StixObject) => {
  try {
    const splitter = new Stix2Splitter();
    return splitter.splitBundleWithExpectations(bundle, false, dictGet(bundle, 'x_opencti_event_version'));
  } catch (error) {
    if (error instanceof StixImportError) {
      throw error;
    }
    throw new StixImportError((error as Error).name as PythonErrorName, (error as Error).message, { cause: error });
  }
};

export const transformBundle = async (context: ImportContext, bundle: StixObject, update: boolean, types: string[] | null): Promise<TransformResult> => {
  const { bundles, incompatibleItems } = splitBundle(bundle);
  const items: TransformResult['items'] = [];
  for (const splitBundle of bundles as StixObject[]) {
    for (const item of splitBundle.objects as StixObject[]) {
      const itemId = item.id;
      // The logs of this object carry its id
      const itemContext = { ...context, logger: withObjectId(context.logger, itemId) };
      try {
        await importItem(itemContext, item, update, types, splitBundle.id);
        items.push({ id: itemId, outcome: 'transformed' });
      } catch (error) {
        items.push({ id: itemId, outcome: pythonOutcome(error) });
      }
    }
  }
  return { items, incompatible: incompatibleItems.map((item) => item.id) };
};

// The operations of a stream event the worker handles (push_handler.py match on content["type"])
const EVENT_OPERATIONS = new Set(['create', 'update', 'merge', 'delete', 'restore', 'delete_force', 'share', 'unshare', 'rule_apply',
  'rule_clear', 'rules_rescan', 'enrichment', 'clear_access_restriction', 'add_related_covered_entities', 'revert_draft']);

// The bundle the worker builds from a stream event (opencti-worker push_handler.py), with its
// Python semantics: a missing key, a value of the wrong type or an unknown operation fails the
// message as it does there
export const eventBundle = (event: StixObject): StixObject => {
  const eventType = required(event, 'type');
  if (!EVENT_OPERATIONS.has(eventType)) {
    throw new StixImportError('ValueError', 'Unsupported operation type');
  }
  const data = required(event, 'data');
  if (eventType === 'merge') {
    setItem(data, 'opencti_operation', eventType);
    setItem(data, 'merge_target_id', required(data, 'id'));
    setItem(data, 'merge_source_ids', iterate(required(required(event, 'context'), 'sources')).map((source) => required(source, 'id')));
  } else if (eventType !== 'create' && eventType !== 'update') {
    setItem(data, 'opencti_operation', eventType);
  }
  return { type: 'bundle', objects: [data] };
};
