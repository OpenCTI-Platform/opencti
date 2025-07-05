import type { StixDomainObject, StixOpenctiExtensionSDO } from '../../../../types/stix-2-1-common';
import { STIX_EXT_OCTI } from '../../../../types/stix-2-1-extensions';

export interface StixFeedback extends StixDomainObject {
  name: string,
  description: string,
  content: string,
  content_mapping: string,
  rating: number,
  object_refs: Array<string>,
  extensions: {
    [STIX_EXT_OCTI]: StixOpenctiExtensionSDO
  }
}
