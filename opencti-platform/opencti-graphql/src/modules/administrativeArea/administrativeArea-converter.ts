import { convertLocationToStix } from '../../database/stix-2-1-converter';
import type { StoreEntityAdministrativeArea } from './administrativeArea-types';
import { ENTITY_TYPE_LOCATION_ADMINISTRATIVE_AREA } from './administrativeArea-types';
import type * as SDO from '../../types/stix-2-1-sdo';

const convertAdministrativeAreaToStix = (instance: StoreEntityAdministrativeArea): SDO.StixLocation => {
  return convertLocationToStix(instance, ENTITY_TYPE_LOCATION_ADMINISTRATIVE_AREA);
};

export default convertAdministrativeAreaToStix;
