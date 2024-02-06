import { convertLocationToStix } from '../../database/stix-converter';
import { ENTITY_TYPE_LOCATION_ADMINISTRATIVE_AREA } from './administrativeArea-types';
const convertAdministrativeAreaToStix = (instance) => {
    return convertLocationToStix(instance, ENTITY_TYPE_LOCATION_ADMINISTRATIVE_AREA);
};
export default convertAdministrativeAreaToStix;
