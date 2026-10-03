import { STIX_EXT_OCTI } from '../../types/stix-2-1-extensions';
import { buildStixObject } from '../../database/stix-2-1-converter';
import { cleanObject } from '../../database/stix-converter-utils';
import type { StixGraphCluster, StixGraphSimilarity, StoreEntityGraphCluster, StoreEntityGraphSimilarity } from './graphAnalytics-types';

export const convertGraphClusterToStix = (instance: StoreEntityGraphCluster): StixGraphCluster => {
  const stixObject = buildStixObject(instance);
  return {
    ...stixObject,
    name: instance.name,
    cluster_id: instance.cluster_id,
    cluster_kind: instance.cluster_kind,
    cluster_source: instance.cluster_source,
    members_count: instance.members_count,
    representative_ids: instance.representative_ids ?? [],
    extensions: {
      [STIX_EXT_OCTI]: cleanObject({
        ...stixObject.extensions[STIX_EXT_OCTI],
        extension_type: 'new-sdo',
      }),
    },
  };
};

export const convertGraphSimilarityToStix = (instance: StoreEntityGraphSimilarity): StixGraphSimilarity => {
  const stixObject = buildStixObject(instance);
  return {
    ...stixObject,
    similarity_entity_id: instance.similarity_entity_id,
    similarity_target_id: instance.similarity_target_id,
    similarity_score: instance.similarity_score,
    extensions: {
      [STIX_EXT_OCTI]: cleanObject({
        ...stixObject.extensions[STIX_EXT_OCTI],
        extension_type: 'new-sdo',
      }),
    },
  };
};
