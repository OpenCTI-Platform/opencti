import financialDataTypeDefs from './financialData.graphql';
import { type ModuleDefinition, registerDefinition } from '../../schema/module';
import {
  ENTITY_TYPE_FINANCIAL_ACCOUNT,
  ENTITY_TYPE_FINANCIAL_ASSET,
  type StoreEntityFinancialAccount,
  type StoreEntityFinancialAsset,
} from './financialData-types';
import {
  financialAccountResolvers,
  financialAssetResolvers,
} from './financialData-resolver';
import { NAME_FIELD, normalizeName } from '../../schema/identifier';
import type {
  StixFinancialAccount,
  StixFinancialAsset,
} from '../../types/stix-sdo';
import {
  convertFinancialAccountToStix,
  convertFinancialAssetToStix,
} from '../../database/stix-converter';
import {
  RELATION_LOCATED_AT,
} from '../../schema/stixCoreRelationship';
import { REL_EXTENDED } from '../../database/stix';
import {
  ENTITY_TYPE_LOCATION_CITY,
  ENTITY_TYPE_LOCATION_COUNTRY,
  ENTITY_TYPE_LOCATION_POSITION,
  ENTITY_TYPE_LOCATION_REGION,
} from '../../schema/stixDomainObject';
import { ENTITY_TYPE_LOCATION_ADMINISTRATIVE_AREA } from '../administrativeArea/administrativeArea-types';
import type { JSONSchemaType } from 'ajv';

interface Balance {
  as_of_date: object | string | null
  balance: number | null
};
// eslint-disable-next-line @typescript-eslint/ban-ts-comment
// @ts-ignore
export const schemaBalance: JSONSchemaType<Balance[]> = {
  type: 'array',
  items: {
    type: 'object',
    properties: {
      as_of_date: { type: ['null', 'string', 'object'] },
      balance: { type: ['null', 'number'] },
    },
    required: ['as_of_date', 'balance'],
  },
};

const FINANCIAL_ACCOUNT_DEFINITION: ModuleDefinition<StoreEntityFinancialAccount, StixFinancialAccount> = {
  type: {
    id: 'financialAccounts',
    name: ENTITY_TYPE_FINANCIAL_ACCOUNT,
    category: 'Stix-Domain-Object',
    aliased: true,
  },
  graphql: {
    schema: financialDataTypeDefs,
    resolver: financialAccountResolvers,
  },
  identifier: {
    definition: {
      [ENTITY_TYPE_FINANCIAL_ACCOUNT]: [{ src: NAME_FIELD }],
    },
    resolvers: {
      name(data: object) {
        return normalizeName(data);
      },
    },
  },
  attributes: [
    { name: 'name', type: 'string', mandatoryType: 'external', multiple: false, upsert: true },
    { name: 'currency_code', type: 'string', mandatoryType: 'no', multiple: false, upsert: true },
    { name: 'financial_account_number', type: 'string', mandatoryType: 'no', multiple: false, upsert: true },
    { name: 'financial_account_status', type: 'string', mandatoryType: 'no', multiple: false, upsert: true },
    { name: 'financial_account_type', type: 'string', mandatoryType: 'no', multiple: false, upsert: true },
    { name: 'financial_account_balances', type: 'object', mandatoryType: 'no', multiple: true, upsert: true, schemaDef: schemaBalance },
    { name: 'international_bank_account_number', type: 'string', mandatoryType: 'no', multiple: false, upsert: true },
  ],
  relations: [],
  representative(instance: StixFinancialAccount): string {
    return instance.name;
  },
  converter: convertFinancialAccountToStix,
};

const FINANCIAL_ASSET_DEFINITION: ModuleDefinition<StoreEntityFinancialAsset, StixFinancialAsset> = {
  type: {
    id: 'financialAssets',
    name: ENTITY_TYPE_FINANCIAL_ASSET,
    category: 'Stix-Domain-Object',
    aliased: true,
  },
  graphql: {
    schema: financialDataTypeDefs,
    resolver: financialAssetResolvers,
  },
  identifier: {
    definition: {
      [ENTITY_TYPE_FINANCIAL_ASSET]: [{ src: NAME_FIELD }],
    },
    resolvers: {
      name(data: object) {
        return normalizeName(data);
      },
    },
  },
  attributes: [
    { name: 'name', type: 'string', mandatoryType: 'external', multiple: false, upsert: true },
    { name: 'asset_type', type: 'string', mandatoryType: 'external', multiple: false, upsert: true },
    { name: 'asset_value', type: 'numeric', mandatoryType: 'external', multiple: false, upsert: true },
  ],
  relations: [
    {
      name: RELATION_LOCATED_AT,
      targets: [
        { name: ENTITY_TYPE_LOCATION_REGION, type: REL_EXTENDED },
        { name: ENTITY_TYPE_LOCATION_COUNTRY, type: REL_EXTENDED },
        { name: ENTITY_TYPE_LOCATION_ADMINISTRATIVE_AREA, type: REL_EXTENDED },
        { name: ENTITY_TYPE_LOCATION_CITY, type: REL_EXTENDED },
        { name: ENTITY_TYPE_LOCATION_POSITION, type: REL_EXTENDED },
      ],
    },
  ],
  representative(instance: StixFinancialAsset): string {
    return instance.name;
  },
  converter: convertFinancialAssetToStix,
};

registerDefinition(FINANCIAL_ACCOUNT_DEFINITION);
registerDefinition(FINANCIAL_ASSET_DEFINITION);
