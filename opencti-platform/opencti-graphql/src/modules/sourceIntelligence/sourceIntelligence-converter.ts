import { buildStixObject } from '../../database/stix-2-1-converter';
import { STIX_EXT_OCTI } from '../../types/stix-2-1-extensions';
import { cleanObject } from '../../database/stix-converter-utils';
import type {
  StixCollectionGap,
  StixSource,
  StixSourceRecommendation,
  StoreEntityCollectionGap,
  StoreEntitySource,
  StoreEntitySourceRecommendation,
} from './sourceIntelligence-types';

export const convertSourceToStix = (instance: StoreEntitySource): StixSource => {
  const stixObject = buildStixObject(instance);
  return {
    ...stixObject,
    name: instance.name,
    description: instance.description,
    source_kind: instance.source_kind,
    ref_id: instance.ref_id,
    extensions: {
      [STIX_EXT_OCTI]: cleanObject({
        ...stixObject.extensions[STIX_EXT_OCTI],
        extension_type: 'new-sdo',
      }),
    },
  };
};

export const convertCollectionGapToStix = (instance: StoreEntityCollectionGap): StixCollectionGap => {
  const stixObject = buildStixObject(instance);
  return {
    ...stixObject,
    name: instance.name,
    pir_id: instance.pir_id,
    coverage_score: instance.gap_coverage_score,
    extensions: {
      [STIX_EXT_OCTI]: cleanObject({
        ...stixObject.extensions[STIX_EXT_OCTI],
        extension_type: 'new-sdo',
      }),
    },
  };
};

export const convertSourceRecommendationToStix = (instance: StoreEntitySourceRecommendation): StixSourceRecommendation => {
  const stixObject = buildStixObject(instance);
  return {
    ...stixObject,
    name: instance.name,
    recommendation_kind: instance.recommendation_kind,
    recommendation_status: instance.recommendation_status,
    extensions: {
      [STIX_EXT_OCTI]: cleanObject({
        ...stixObject.extensions[STIX_EXT_OCTI],
        extension_type: 'new-sdo',
      }),
    },
  };
};
