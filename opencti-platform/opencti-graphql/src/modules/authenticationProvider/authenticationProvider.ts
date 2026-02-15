import { v4 as uuidv4 } from 'uuid';
import { type ModuleDefinition, registerDefinition } from '../../schema/module';
import { ENTITY_TYPE_AUTHENTICATION_PROVIDER, type StixAuthenticationProvider, type StoreEntityAuthenticationProvider } from './authenticationProvider-types';
import { ABSTRACT_INTERNAL_OBJECT } from '../../schema/general';
import convertAuthenticationProviderToStix from './authenticationProvider-converter';
import { isFeatureEnabled } from '../../config/conf';
import { AuthenticationProviderType } from '../../generated/graphql';
import { draftChange, refreshedAt } from '../../schema/attribute-definition';

const AuthenticationProviderTypeList = Object.values(AuthenticationProviderType);

export const AUTHENTICATION_PROVIDER_IN_UI_FF = 'AUTHENTICATION_PROVIDER_IN_UI_ENABLED';

const AUTHENTICATION_PROVIDER_DEFINITION: ModuleDefinition<StoreEntityAuthenticationProvider, StixAuthenticationProvider> = {
  type: {
    id: 'authenticationProvider',
    name: ENTITY_TYPE_AUTHENTICATION_PROVIDER,
    category: ABSTRACT_INTERNAL_OBJECT,
    aliased: false,
  },
  identifier: {
    definition: {
      [ENTITY_TYPE_AUTHENTICATION_PROVIDER]: () => uuidv4(),
    },
  },
  attributes: [
    { name: 'name', label: 'Authentication name', type: 'string', mandatoryType: 'internal', format: 'short', editDefault: false, multiple: false, upsert: false, isFilterable: true },
    { name: 'identifier', label: 'Provider identifier', type: 'string', mandatoryType: 'internal', format: 'short', editDefault: false, multiple: false, upsert: false, isFilterable: true },
    { name: 'description', label: 'Description', mandatoryType: 'customizable', type: 'string', format: 'text', editDefault: false, multiple: false, upsert: false, isFilterable: true },
    { name: 'enabled', label: 'Enabled', type: 'boolean', mandatoryType: 'no', editDefault: false, multiple: false, upsert: false, isFilterable: true },
    { name: 'type', label: 'Type', mandatoryType: 'internal', type: 'string', format: 'enum', values: AuthenticationProviderTypeList, editDefault: false, multiple: false, upsert: false, isFilterable: true },
    { name: 'button_label', label: 'Button display name', mandatoryType: 'no', type: 'string', format: 'short', editDefault: false, multiple: false, upsert: false, isFilterable: true },
    { name: 'configuration', label: 'Provider Configuration', mandatoryType: 'no', type: 'object', format: 'flat', editDefault: false, multiple: true, upsert: false, isFilterable: false },
    { ...draftChange, isFilterable: false },
    { ...refreshedAt, isFilterable: false },
  ],
  relations: [],
  representative: (stix: StixAuthenticationProvider) => {
    return stix.name;
  },
  converter_2_1: convertAuthenticationProviderToStix,
};

export const isAuthenticationProviderInGuiEnabled = isFeatureEnabled(AUTHENTICATION_PROVIDER_IN_UI_FF);
registerDefinition(AUTHENTICATION_PROVIDER_DEFINITION);
