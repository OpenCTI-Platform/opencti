import { describe, expect, it } from 'vitest';
import { ENTITY_TYPE_GRAPH_CLUSTER, ENTITY_TYPE_GRAPH_SIMILARITY } from '../../../../src/modules/graphAnalytics/graphAnalytics-types';
import { generateStandardId } from '../../../../src/schema/identifier';

import '../../../../src/modules/graphAnalytics/graphAnalytics';

describe('Graph analytics identifiers', () => {
  it('should generate a deterministic cluster identifier from the cluster id', () => {
    const first = generateStandardId(ENTITY_TYPE_GRAPH_CLUSTER, { cluster_id: '155deb88-fd53-5237-b6fa-05f09a5983af' });
    const again = generateStandardId(ENTITY_TYPE_GRAPH_CLUSTER, { cluster_id: '155deb88-fd53-5237-b6fa-05f09a5983af' });
    const other = generateStandardId(ENTITY_TYPE_GRAPH_CLUSTER, { cluster_id: '255deb88-fd53-5237-b6fa-05f09a5983af' });
    expect(first).toMatch(/^graph-cluster--/);
    expect(again).toEqual(first);
    expect(other).not.toEqual(first);
  });

  it('should generate a directed similarity identifier from both entities', () => {
    const forward = generateStandardId(ENTITY_TYPE_GRAPH_SIMILARITY, { similarity_entity_id: 'a', similarity_target_id: 'b' });
    const again = generateStandardId(ENTITY_TYPE_GRAPH_SIMILARITY, { similarity_entity_id: 'a', similarity_target_id: 'b' });
    const reverse = generateStandardId(ENTITY_TYPE_GRAPH_SIMILARITY, { similarity_entity_id: 'b', similarity_target_id: 'a' });
    expect(forward).toMatch(/^graph-similarity--/);
    expect(again).toEqual(forward);
    expect(reverse).not.toEqual(forward);
  });
});
