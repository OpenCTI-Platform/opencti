import type { StoreCommon } from '../types/store';
import { Version } from '../generated/graphql';
import type * as S from '../types/stix-2-1-common';
import type * as S2 from '../types/stix-2-0-common';
import { convertStoreToStix_2_0 } from './stix-2-0-converter';
import { convertStoreToStix_2_1 } from './stix-2-1-converter';

export const convertStoreToStix = (instance: StoreCommon, version = Version.Stix_2_1): S.StixObject | S2.StixObject => {
  return version === Version.Stix_2_0 ? convertStoreToStix_2_0(instance) : convertStoreToStix_2_1(instance);
};
