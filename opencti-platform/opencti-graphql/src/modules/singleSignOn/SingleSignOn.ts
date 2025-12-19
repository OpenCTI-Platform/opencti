import { v4 as uuidv4 } from 'uuid';
import { type ModuleDefinition, registerDefinition } from '../../schema/module';
import { ENTITY_TYPE_SINGLE_SIGN_ON, type StixSingleSignOn, type StoreEntitySingleSignOn } from './SingleSignOn-types';
import { ABSTRACT_INTERNAL_OBJECT } from '../../schema/general';
import convertSingleSignOnToStix from './SingleSignOn-converter';
import { isFeatureEnabled } from '../../config/conf';
import { StrategyType } from '../../config/providers-configuration';

const StrategyTypeList = Object.values(StrategyType);

const SINGLE_SIGN_ON_DEFINITION: ModuleDefinition<StoreEntitySingleSignOn, StixSingleSignOn> = {
  type: {
    id: 'singleSignOn',
    name: ENTITY_TYPE_SINGLE_SIGN_ON,
    category: ABSTRACT_INTERNAL_OBJECT,
    aliased: false,
  },
  identifier: {
    definition: {
      [ENTITY_TYPE_SINGLE_SIGN_ON]: () => uuidv4(),
    },
  },
  attributes: [
    { name: 'name', label: "Name", type: 'string', mandatoryType: 'internal', format: 'short', editDefault: false, multiple: false, upsert: false, isFilterable: true },
    { name: 'description', label: 'Description', mandatoryType: 'customizable', type: 'string', format: 'text', editDefault: false, multiple: false, upsert: false, isFilterable: true },
    { name: 'enabled', label: 'Enabled', type: 'boolean', mandatoryType: 'no', editDefault: false, multiple: false, upsert: false, isFilterable: true },
    { name: 'strategy', label: 'Strategy', mandatoryType: 'internal', type: 'string', format: 'enum', values: StrategyTypeList, editDefault: false, multiple: false, upsert: false, isFilterable: true },
    { name: 'label', label: 'Label', mandatoryType: 'no', type: 'string', format: 'short', editDefault: false, multiple: false, upsert: false, isFilterable: true },
    { name: 'auto_create_group', label: 'Auto create group', mandatoryType: 'no', type: 'boolean', editDefault: false, multiple: false, upsert: true, isFilterable: true },
    { name: 'prevent_default_groups', label: 'Prevent default groups', mandatoryType: 'no', type: 'boolean', editDefault: false, multiple: false, upsert: true, isFilterable: true },
    { name: 'logout_remote', label: 'Logout remote', mandatoryType: 'no', type: 'boolean', editDefault: false, multiple: false, upsert: false, isFilterable: true },
    { name: 'organizations_management', label: 'Organizations management', mandatoryType: 'no', type: 'object', format: 'flat', editDefault: false, multiple: true, upsert: false, isFilterable: false },
    { name: 'groups_management', label: 'Groups management', mandatoryType: 'no', type: 'object', format: 'flat', editDefault: false, multiple: true, upsert: false, isFilterable: false },
    { name: 'configuration', label: 'SSO Configuration', mandatoryType: 'no', type: 'object', format: 'flat', editDefault: false, multiple: true, upsert: false, isFilterable: false },
    { name: 'advanced_configuration', label: 'SSO Advanced configuration', mandatoryType: 'no', type: 'object', format: 'flat', editDefault: false, multiple: true, upsert: false, isFilterable: false },
  ],
  relations: [],
  representative: (stix: StixSingleSignOn) => {
    return stix.name
  },
  converter_2_1: convertSingleSignOnToStix
};

const isSingleSignOnEnabled = isFeatureEnabled('SINGLE_SIGN_ON_ENABLED');

if (isSingleSignOnEnabled) {
  registerDefinition(SINGLE_SIGN_ON_DEFINITION);
}
