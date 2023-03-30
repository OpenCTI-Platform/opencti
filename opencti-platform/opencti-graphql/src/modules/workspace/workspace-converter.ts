import { STIX_EXT_OCTI } from '../../types/stix-extensions';
import { buildStixDomain, cleanObject, convertObjectReferences } from '../../database/stix-converter';
import type { StixWorkspace, StoreEntityWorkspace } from './workspace-types';

const convertWorkspaceToStix = (instance: StoreEntityWorkspace): StixWorkspace => {
  const stixDomainObject = buildStixDomain(instance);
  return {
    ...stixDomainObject,
    name: instance.name,
    description: instance.description,
    type: instance.type,
    graph_data: instance.graph_data,
    manifest: instance.manifest,
    tags: instance.tags ?? [],
    object_refs: convertObjectReferences(instance),
    aliases: instance.x_opencti_aliases ?? [],
    extensions: {
      [STIX_EXT_OCTI]: cleanObject({
        ...stixDomainObject.extensions[STIX_EXT_OCTI],
        extension_type: 'new-sdo',
        object_refs_inferred: convertObjectReferences(instance, true),
      })
    }
  };
};

export default convertWorkspaceToStix;
