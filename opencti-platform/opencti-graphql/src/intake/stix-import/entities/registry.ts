import type { StixImporter } from '../kwargs';
import { DOMAIN_IMPORTERS } from './registry-domain';
import { CONTAINER_IMPORTERS } from './registry-containers';

// pycti get_stix_helper: the importer of each STIX type that goes through import_object
export const STIX_IMPORTERS: Record<string, StixImporter> = {
  ...DOMAIN_IMPORTERS,
  ...CONTAINER_IMPORTERS,
};
