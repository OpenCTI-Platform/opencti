// Chunk-queue intake: response selections the chunk manager never reads (see chunk-executor.ts).
// A field whose selection reads `edges` is a paginated connection resolved by a listing
// query: dropped from the document. Scalars and nested object selections are kept.
import { Kind, visit } from 'graphql';
import type { DocumentNode, FieldNode } from 'graphql';

const isConnectionSelection = (node: FieldNode) => !!node.selectionSet?.selections
  .some((selection) => selection.kind === Kind.FIELD && selection.name.value === 'edges');

export const pruneResponseConnections = (document: DocumentNode): DocumentNode => visit(document, {
  Field: {
    leave: (node) => (isConnectionSelection(node) ? null : undefined),
  },
});
