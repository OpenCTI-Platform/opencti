import { convertLocationToStix } from '../../database/stix-2-1-converter';
import { convertLocationToStix as convertLocationToStix_2_0 } from '../../database/stix-2-0-converter';
import type { StoreEntityAdministrativeArea } from './administrativeArea-types';
import { ENTITY_TYPE_LOCATION_ADMINISTRATIVE_AREA } from './administrativeArea-types';
import type * as SDO from '../../types/stix-2-1-sdo';
import type * as SDO2 from '../../types/stix-2-0-sdo';
import type { StoreEntity } from '../../types/store';
import { assertType } from '../../database/stix-converter-utils';

const convertAdministrativeAreaToStix = (instance: StoreEntityAdministrativeArea): SDO.StixLocation => {
  return convertLocationToStix(instance, ENTITY_TYPE_LOCATION_ADMINISTRATIVE_AREA);
};

export const convertAdministrativeAreaToStix_2_0 = (instance: StoreEntity): SDO2.StixLocation => {
  assertType(ENTITY_TYPE_LOCATION_ADMINISTRATIVE_AREA, instance.entity_type);
  return convertLocationToStix_2_0(instance, instance.entity_type);
};

export default convertAdministrativeAreaToStix;
