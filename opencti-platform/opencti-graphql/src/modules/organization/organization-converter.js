import { convertIdentityToStix } from '../../database/stix-converter';
const convertOrganizationToStix = (instance) => {
    return convertIdentityToStix(instance, instance.entity_type);
};
export default convertOrganizationToStix;
