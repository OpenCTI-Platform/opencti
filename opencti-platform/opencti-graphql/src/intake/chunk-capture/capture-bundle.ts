import type { ChunkOperation } from '../../graphql/chunk-executor';
import { Stix2Splitter } from '../../utils/stix2-splitter';
import type { ImportContext } from '../stix-import/context';
import { transformBundle } from '../stix-import/transform';
import type { StixObject } from '../stix-import/types';
import { CaptureCache, purgeCaptureWindow } from './capture-cache';
import { ChunkCaptureClient } from './capture-client';
import { type ChunkContent, chunkContents, markMemberRefs } from './chunks';

// One bundle into chunks, as the worker publishes it (push_handler.py publish_bundle_chunks):
// split, mark the in-bundle refs, transform each split bundle with its mutations captured, then
// group the operations into chunks. What surrounds it in the worker (work expectations, too large
// objects, the envelope of the chunk messages) belongs to the intake manager. A bundle with files,
// that the worker imports over HTTP, is captured too: its files stay in memory (file-values.ts).

export interface CapturedOperations {
  // The captured operations, in capture order
  operations: ChunkOperation[];
  // Per object outcome of the transformation (transformed, or the Python error name)
  items: { id: string; outcome: string }[];
  // Objects the split sets aside
  incompatible: string[];
}

export interface CapturedBundle extends CapturedOperations {
  chunks: ChunkContent[];
  // Echoes referenced and produced by no operation of the bundle: must stay empty
  dangling: string[];
}

// One bundle into its operations: split, mark the in-bundle refs, transform each split bundle with
// its mutations captured (the worker-less intake runs them as a graph, operation-graph.ts)
export const captureOperations = async (context: ImportContext, bundle: StixObject, update: boolean, types: string[] | null): Promise<CapturedOperations> => {
  const { bundles, incompatibleItems } = new Stix2Splitter().splitBundleWithExpectations(bundle, false, bundle.x_opencti_event_version);
  const memberIds = new Set((bundle.objects as StixObject[]).filter((object) => typeof object?.id === 'string').map((object) => object.id as string));
  (bundles as StixObject[]).forEach((splitBundle) => (splitBundle.objects as StixObject[]).forEach((object) => markMemberRefs(object, memberIds)));
  const client = new ChunkCaptureClient(context.client);
  const captureContext: ImportContext = { ...context, client, cache: new CaptureCache(context.cache, client.window) };
  const items: CapturedOperations['items'] = [];
  try {
    // The worker imports each split bundle on its own (import_bundle_from_json splits it again)
    for (const splitBundle of bundles as StixObject[]) {
      const result = await transformBundle(captureContext, splitBundle, update, types);
      items.push(...result.items);
    }
  } finally {
    purgeCaptureWindow(context.cache, client.window);
  }
  return { operations: client.operations, items, incompatible: incompatibleItems.map((item: StixObject) => item.id as string) };
};

// One bundle into chunks, as the worker publishes them (the chunk queue path)
export const captureBundle = async (context: ImportContext, bundle: StixObject, update: boolean, types: string[] | null, chunkSize: number): Promise<CapturedBundle> => {
  const captured = await captureOperations(context, bundle, update, types);
  const dangling = new Set<string>();
  const chunks = chunkContents(captured.operations, Math.max(1, chunkSize), dangling);
  return { ...captured, chunks, dangling: [...dangling] };
};
