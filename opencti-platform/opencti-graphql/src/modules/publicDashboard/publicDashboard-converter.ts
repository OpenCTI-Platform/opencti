import { STIX_EXT_OCTI } from '../../types/stix-extensions';
import { buildStixDomain, cleanObject } from '../../database/stix-converter';
import type { StixPublicDashboard, StoreEntityPublicDashboard } from './publicDashboard-types';

const convertPublicDashboardToStix = (instance: StoreEntityPublicDashboard): StixPublicDashboard => {
  const stixDomainObject = buildStixDomain(instance);
  return {
    ...stixDomainObject,
    name: instance.name,
    description: instance.description,
    dashboard_id: instance.dashboard_id,
    user_id: instance.user_id,
    public_manifest: instance.public_manifest,
    private_manifest: instance.private_manifest,
    uri_key: instance.uri_key,
    allowed_markings_ids: instance.allowed_markings_ids,
    allowed_markings: instance.allowed_markings,
    extensions: {
      [STIX_EXT_OCTI]: cleanObject({
        ...stixDomainObject.extensions[STIX_EXT_OCTI],
        extension_type: 'new-sdo',
      })
    }
  };
};

export default convertPublicDashboardToStix;
