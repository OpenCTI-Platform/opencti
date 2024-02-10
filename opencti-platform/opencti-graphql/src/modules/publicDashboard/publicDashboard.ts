import { v4 as uuidv4 } from 'uuid';
import { ABSTRACT_INTERNAL_OBJECT } from '../../schema/general';
import type { ModuleDefinition } from '../../schema/module';
import { registerDefinition } from '../../schema/module';
import { ENTITY_TYPE_PUBLIC_DASHBOARD, type StixPublicDashboard, type StoreEntityPublicDashboard } from './publicDashboard-types';
import convertPublicDashboardToStix from './publicDashboard-converter';
import { authorizedMembers } from '../../schema/attribute-definition';

export const PUBLIC_DASHBOARD_DEFINITION: ModuleDefinition<StoreEntityPublicDashboard, StixPublicDashboard> = {
  type: {
    id: 'publicDashboards',
    name: ENTITY_TYPE_PUBLIC_DASHBOARD,
    category: ABSTRACT_INTERNAL_OBJECT,
    aliased: false
  },
  identifier: {
    definition: {
      [ENTITY_TYPE_PUBLIC_DASHBOARD]: () => uuidv4(),
    },
  },
  attributes: [
    { name: 'name', label: 'Name', type: 'string', format: 'short', mandatoryType: 'external', editDefault: false, multiple: false, upsert: false, isFilterable: true },
    { name: 'description', label: 'Description', type: 'string', format: 'text', mandatoryType: 'no', editDefault: false, multiple: false, upsert: true, isFilterable: true },
    { name: 'dashboard_id', label: 'Dashboard id', type: 'string', format: 'short', mandatoryType: 'external', editDefault: false, multiple: false, upsert: false, isFilterable: true },
    { name: 'public_manifest', label: 'Public manifest', type: 'string', format: 'short', mandatoryType: 'internal', editDefault: false, multiple: false, upsert: false, isFilterable: false },
    { name: 'private_manifest', label: 'Public manifest', type: 'string', format: 'short', mandatoryType: 'internal', editDefault: false, multiple: false, upsert: false, isFilterable: false },
    { name: 'uri_key', label: 'Uri key', type: 'string', format: 'short', mandatoryType: 'external', editDefault: false, multiple: false, upsert: false, isFilterable: true },
    { name: 'allowed_markings_ids', label: 'Allowed markings', type: 'string', format: 'short', mandatoryType: 'external', editDefault: false, multiple: true, upsert: true, isFilterable: false },
    authorizedMembers
  ],
  relations: [],
  representative: (stix: StixPublicDashboard) => {
    return stix.name;
  },
  converter: convertPublicDashboardToStix
};

registerDefinition(PUBLIC_DASHBOARD_DEFINITION);
