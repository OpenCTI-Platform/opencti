import { convertLocationToStix } from '../../database/stix-converter-2-1';
import type { StoreEntityAdministrativeArea } from './administrativeArea-types';
import { ENTITY_TYPE_LOCATION_ADMINISTRATIVE_AREA } from './administrativeArea-types';
import type * as SDO from '../../types/stix-sdo';

const convertAdministrativeAreaToStix = (instance: StoreEntityAdministrativeArea): SDO.StixLocation => {
  return convertLocationToStix(instance, ENTITY_TYPE_LOCATION_ADMINISTRATIVE_AREA);
};

export default convertAdministrativeAreaToStix;
