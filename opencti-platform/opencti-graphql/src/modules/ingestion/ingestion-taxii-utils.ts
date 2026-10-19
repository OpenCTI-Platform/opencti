import { isNotEmptyField } from '../../database/utils';
import { STIX_EXT_OCTI } from '../../types/stix-2-1-extensions';
import type { StixObject } from '../../types/stix-2-1-common';
import type { StixIndicator } from '../indicator/indicator-types';
import type { BasicStoreEntityIngestionTaxii, BasicStoreEntityIngestionTaxiiCollection } from './ingestion-types';

/**
 * When the feed has `confidence_to_score` enabled, copies each indicator's confidence
 * into its OpenCTI score extension. Other objects are returned unchanged.
 * Shared by the TAXII feeds (pulled by the ingestion manager) and the TAXII push collections.
 */
export const handleConfidenceToScoreTransformation = (ingestion: BasicStoreEntityIngestionTaxii | BasicStoreEntityIngestionTaxiiCollection, objects: StixObject[]) => {
  if (ingestion.confidence_to_score === true) {
    return objects.map((o) => {
      if (o.type === 'indicator') {
        const indicator = o as StixIndicator;
        if (isNotEmptyField(indicator.confidence)) {
          if (indicator.extensions && indicator.extensions[STIX_EXT_OCTI]) {
            indicator.extensions[STIX_EXT_OCTI].score = indicator.confidence;
          } else if (indicator.extensions) {
            // eslint-disable-next-line @typescript-eslint/ban-ts-comment
            // @ts-expect-error
            indicator.extensions[STIX_EXT_OCTI] = { score: indicator.confidence };
          } else {
            // eslint-disable-next-line @typescript-eslint/ban-ts-comment
            // @ts-expect-error
            indicator.extensions = { [STIX_EXT_OCTI]: { score: indicator.confidence } };
          }
          return indicator;
        }
      }
      return o;
    });
  }
  return objects;
};
