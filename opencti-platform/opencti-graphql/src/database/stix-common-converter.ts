import type { StoreCommon } from '../types/store';
import { Version } from '../generated/graphql';
import type * as S from '../types/stix-2-1-common';
import type * as S2 from '../types/stix-2-0-common';
import { isEmptyField } from './utils';
import { FunctionalError, UnsupportedError } from '../config/errors';
import { convertToStix_2_0 } from './stix-2-0-converter';
import { convertToStix } from './stix-2-1-converter';
import { cleanObject, isValidStix } from './stix-converter-utils';

export const convertStoreToStix = (instance: StoreCommon, version = Version.Stix_2_1): S.StixObject | S2.StixObject => {
  if (isEmptyField(instance.standard_id) || isEmptyField(instance.entity_type)) {
    throw UnsupportedError('convertInstanceToStix must be used with opencti fully loaded instance');
  }
  const converted = version === Version.Stix_2_0 ? convertToStix_2_0(instance) : convertToStix(instance);
  const stix = cleanObject(converted);
  if (!isValidStix(stix)) {
    throw FunctionalError('Invalid stix data conversion', { id: instance.standard_id, type: instance.entity_type });
  }
  return stix;
};
