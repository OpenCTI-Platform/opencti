import { Stix2Splitter } from '../../utils/stix2-splitter';
import type { ImportContext } from '../stix-import/context';
import { transformBundle } from '../stix-import/transform';
import type { StixObject } from '../stix-import/types';
import { CaptureCache, purgeCaptureWindow } from './capture-cache';
import { ChunkCaptureClient, NotChunkableError } from './capture-client';
import { type ChunkContent, chunkContents, markMemberRefs } from './chunks';

// One bundle into chunks, as the worker publishes it (push_handler.py publish_bundle_chunks):
// split, mark the in-bundle refs, transform each split bundle with its mutations captured, then
// group the operations into chunks. What surrounds it in the worker (work expectations, too large
// objects, the envelope of the chunk messages) belongs to the intake manager.

// The worker sends a bundle with files over HTTP: a queue message cannot carry a file
const carriesFiles = (node: unknown): boolean => {
  if (Array.isArray(node)) {
    return node.some(carriesFiles);
  }
  if (node !== null && typeof node === 'object') {
    const record = node as Record<string, unknown>;
    if (record.x_opencti_files || record.x_opencti_file) {
      return true;
    }
    return Object.values(record).some(carriesFiles);
  }
  return false;
};

export interface CapturedBundle {
  chunks: ChunkContent[];
  // Per object outcome of the transformation (transformed, or the Python error name)
  items: { id: string; outcome: string }[];
  // Objects the split sets aside
  incompatible: string[];
  // Echoes referenced and produced by no operation of the bundle: must stay empty
  dangling: string[];
}

export const captureBundle = async (context: ImportContext, bundle: StixObject, update: boolean, types: string[] | null, chunkSize: number): Promise<CapturedBundle> => {
  if (carriesFiles(bundle.objects)) {
    throw new NotChunkableError('files');
  }
  const { bundles, incompatibleItems } = new Stix2Splitter().splitBundleWithExpectations(bundle, false, bundle.x_opencti_event_version);
  const memberIds = new Set((bundle.objects as StixObject[]).filter((object) => typeof object?.id === 'string').map((object) => object.id as string));
  (bundles as StixObject[]).forEach((splitBundle) => (splitBundle.objects as StixObject[]).forEach((object) => markMemberRefs(object, memberIds)));
  const client = new ChunkCaptureClient(context.client);
  const captureContext: ImportContext = { ...context, client, cache: new CaptureCache(context.cache, client.window) };
  const items: CapturedBundle['items'] = [];
  try {
    // The worker imports each split bundle on its own (import_bundle_from_json splits it again)
    for (const splitBundle of bundles as StixObject[]) {
      const result = await transformBundle(captureContext, splitBundle, update, types);
      items.push(...result.items);
    }
  } finally {
    purgeCaptureWindow(context.cache, client.window);
  }
  const dangling = new Set<string>();
  const chunks = chunkContents(client.operations, Math.max(1, chunkSize), dangling);
  return { chunks, items, incompatible: incompatibleItems.map((item: StixObject) => item.id as string), dangling: [...dangling] };
};
