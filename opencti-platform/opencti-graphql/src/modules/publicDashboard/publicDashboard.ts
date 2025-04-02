import { v4 as uuidv4 } from 'uuid';
import { ABSTRACT_INTERNAL_OBJECT } from '../../schema/general';
import type { ModuleDefinition } from '../../schema/module';
import { registerDefinition } from '../../schema/module';
import { ENTITY_TYPE_PUBLIC_DASHBOARD, type StixPublicDashboard, type StoreEntityPublicDashboard } from './publicDashboard-types';
import convertPublicDashboardToStix from './publicDashboard-converter';
import { ENTITY_TYPE_MARKING_DEFINITION } from '../../schema/stixMetaObject';

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
    { name: 'enabled', label: 'Enabled', type: 'boolean', mandatoryType: 'external', editDefault: false, multiple: false, upsert: false, isFilterable: true },
    { name: 'description', label: 'Description', type: 'string', format: 'text', mandatoryType: 'no', editDefault: false, multiple: false, upsert: true, isFilterable: true, update: false },
    { name: 'dashboard_id', label: 'Dashboard', type: 'string', format: 'id', entityTypes: [ENTITY_TYPE_PUBLIC_DASHBOARD], mandatoryType: 'external', editDefault: false, multiple: false, upsert: false, isFilterable: true, update: false },
    { name: 'public_manifest', label: 'Public manifest', type: 'string', format: 'short', mandatoryType: 'internal', editDefault: false, multiple: false, upsert: false, isFilterable: false, update: false },
    { name: 'private_manifest', label: 'Public manifest', type: 'string', format: 'short', mandatoryType: 'internal', editDefault: false, multiple: false, upsert: false, isFilterable: false, update: false },
    { name: 'uri_key', label: 'URI key', type: 'string', format: 'short', mandatoryType: 'external', editDefault: false, multiple: false, upsert: false, isFilterable: true },
    { name: 'allowed_markings_ids', label: 'Allowed markings', type: 'string', format: 'id', entityTypes: [ENTITY_TYPE_MARKING_DEFINITION], mandatoryType: 'external', editDefault: false, multiple: true, upsert: true, isFilterable: true, update: false },
  ],
  relations: [],
  representative: (stix: StixPublicDashboard) => {
    return stix.name;
  },
  converter_2_1: convertPublicDashboardToStix
};

registerDefinition(PUBLIC_DASHBOARD_DEFINITION);
