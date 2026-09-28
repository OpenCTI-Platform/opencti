import { v4 as uuidv4 } from 'uuid';
import { ABSTRACT_INTERNAL_OBJECT } from '../../schema/general';
import { ENTITY_TYPE_CONNECTOR, ENTITY_TYPE_CONNECTOR_MANAGER } from '../../schema/internalObject';
import { registerDefinition, type ModuleDefinition } from '../../schema/module';
import type { StoreEntityConnectorManager, StoreEntityConnector } from './connector-types';
import { updatedAt } from '../../schema/attribute-definition';
import { ConnectorPriorityGroup } from '../../generated/graphql';
import { CATALOG_CONTRACT_MAPPINGS } from '../catalog/catalog';
import { UnsupportedError } from '../../config/errors';

const CONNECTOR_DEFINITION: ModuleDefinition<StoreEntityConnector, any> = {
  type: {
    id: 'connector',
    name: ENTITY_TYPE_CONNECTOR,
    category: ABSTRACT_INTERNAL_OBJECT,
    aliased: false,
  },
  identifier: {
    definition: {
      [ENTITY_TYPE_CONNECTOR]: () => uuidv4(),
    },
  },
  attributes: [
    { ...updatedAt, update: true }, // Allow change of updated_at for connector ping
    { name: 'name', label: 'Name', type: 'string', format: 'short', mandatoryType: 'no', editDefault: false, multiple: false, upsert: false, isFilterable: true },
    { name: 'title', label: 'Title', type: 'string', format: 'short', mandatoryType: 'no', editDefault: false, multiple: false, upsert: false, isFilterable: true },
    { name: 'active', label: 'Status', type: 'boolean', mandatoryType: 'no', editDefault: false, multiple: false, upsert: false, isFilterable: true },
    { name: 'auto', label: 'Auto', type: 'boolean', mandatoryType: 'no', editDefault: false, multiple: false, upsert: false, isFilterable: true },
    { name: 'auto_update', label: 'Auto', type: 'boolean', mandatoryType: 'no', editDefault: false, multiple: false, upsert: false, isFilterable: true },
    { name: 'built_in', label: 'Built-in', type: 'boolean', mandatoryType: 'no', editDefault: false, multiple: false, upsert: false, isFilterable: true },
    { name: 'only_contextual', label: 'Contextual only', type: 'boolean', mandatoryType: 'no', editDefault: false, multiple: false, upsert: false, isFilterable: true },
    { name: 'connector_info', label: 'Connector information', type: 'object', format: 'flat', mandatoryType: 'no', editDefault: false, multiple: false, upsert: true, isFilterable: false },
    { name: 'connector_type', label: 'Connector type', type: 'string', format: 'short', mandatoryType: 'no', editDefault: false, multiple: false, upsert: false, isFilterable: true },
    { name: 'enrichment_resolution', label: 'Enrichment resolution', type: 'string', format: 'short', mandatoryType: 'external', editDefault: false, multiple: false, upsert: false, isFilterable: true },
    { name: 'connector_scope', label: 'Connector scope', type: 'string', format: 'short', mandatoryType: 'external', editDefault: false, multiple: false, upsert: false, isFilterable: true },
    { name: 'connector_state', label: 'Connector state', type: 'string', format: 'json', mandatoryType: 'no', editDefault: false, multiple: false, upsert: false, isFilterable: true },
    { name: 'connector_state_reset', label: 'State reset', type: 'boolean', mandatoryType: 'no', editDefault: false, multiple: false, upsert: false, isFilterable: true },
    { name: 'connector_priority_group', label: 'Priority group', type: 'string', format: 'enum', values: Object.values(ConnectorPriorityGroup), mandatoryType: 'no', editDefault: false, multiple: false, upsert: false, isFilterable: false },
    { name: 'connector_state_timestamp', label: 'State reset timestamp', type: 'date', mandatoryType: 'no', editDefault: false, multiple: false, upsert: false, isFilterable: true },
    { name: 'connector_trigger_filters', label: 'Connector trigger filters', type: 'string', format: 'text', mandatoryType: 'no', editDefault: false, multiple: false, upsert: false, isFilterable: false },
    { name: 'connector_user_id', label: 'Connector user id', type: 'string', format: 'short', mandatoryType: 'no', editDefault: false, multiple: false, upsert: false, isFilterable: false },
    { name: 'playbook_compatible', label: 'Compatible with playbooks', type: 'boolean', mandatoryType: 'no', editDefault: false, multiple: false, upsert: false, isFilterable: true },
    { name: 'listen_callback_uri', label: 'Listen through http callback', type: 'string', format: 'text', mandatoryType: 'no', editDefault: false, multiple: false, upsert: false, isFilterable: false },
    { name: 'xtm_one_intent', label: 'XTM One intent', type: 'string', format: 'short', mandatoryType: 'no', editDefault: false, multiple: false, upsert: true, isFilterable: false },
    // region composer
    { name: 'catalog_id', label: 'Connector catalog', type: 'string', format: 'short', mandatoryType: 'no', editDefault: false, multiple: false, upsert: false, isFilterable: true },
    { name: 'manager_current_status', label: 'Connector manager current status', type: 'string', format: 'short', mandatoryType: 'no', editDefault: false, multiple: false, upsert: false, isFilterable: true },
    { name: 'manager_requested_status', label: 'Connector manager requested status', type: 'string', format: 'short', mandatoryType: 'no', editDefault: false, multiple: false, upsert: false, isFilterable: true },
    { name: 'manager_contract_image', label: 'Connector manager image', type: 'string', format: 'short', mandatoryType: 'no', editDefault: false, multiple: false, upsert: false, isFilterable: true },
    { name: 'manager_contract_configuration', label: 'Connector manager', type: 'object', format: 'flat', mandatoryType: 'no', editDefault: false, multiple: true, upsert: false, isFilterable: true },
    { name: 'manager_contract', label: 'Connector manager contract', type: 'object', format: 'standard', mandatoryType: 'no', editDefault: false, multiple: false, upsert: false, isFilterable: false, mappings: CATALOG_CONTRACT_MAPPINGS },
    { name: 'manager_upgrade_strategy', label: 'Connector upgrade strategy', type: 'string', format: 'enum', values: ['latest'], mandatoryType: 'no', editDefault: false, multiple: false, upsert: false, isFilterable: false },
    // endregion
  ],
  relations: [],
  relationsRefs: [],
  // Irrelevant as no corresponding Stix object.
  // To remove once entity/module definition helper is reworked.
  representative: () => {
    throw UnsupportedError('Connector representative should not be called');
  },
  converter_2_1: () => {
    throw UnsupportedError('Connector converter_2_1 should not be called');
  },
};

registerDefinition(CONNECTOR_DEFINITION);

const CONNECTOR_MANAGER_DEFINITION: ModuleDefinition<StoreEntityConnectorManager, any> = {
  type: {
    id: 'connectorManager',
    name: ENTITY_TYPE_CONNECTOR_MANAGER,
    category: ABSTRACT_INTERNAL_OBJECT,
    aliased: false,
  },
  identifier: {
    definition: {
      [ENTITY_TYPE_CONNECTOR_MANAGER]: () => uuidv4(),
    },
  },
  attributes: [
    { ...updatedAt, update: true }, // Allow change of updated_at for connector ping
    { name: 'name', label: 'Name', type: 'string', format: 'short', mandatoryType: 'no', editDefault: false, multiple: false, upsert: false, isFilterable: true },
    { name: 'public_key', label: 'PublicKey', type: 'string', format: 'short', mandatoryType: 'external', editDefault: false, multiple: false, upsert: false, isFilterable: true },
    { name: 'last_sync_execution', label: 'Last execution', type: 'date', editDefault: false, mandatoryType: 'no', multiple: false, upsert: false, isFilterable: true },
  ],
  relations: [],
  relationsRefs: [],
  representative: () => {
    throw UnsupportedError('Connector manager representative should not be called');
  },
  converter_2_1: () => {
    throw UnsupportedError('Connector manager converter_2_1 should not be called');
  },
};

registerDefinition(CONNECTOR_MANAGER_DEFINITION);
