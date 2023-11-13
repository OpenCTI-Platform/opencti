import type { JSONSchemaType } from 'ajv';
import financialDataTypeDefs from './financialData.graphql';
import { type ModuleDefinition, registerDefinition } from '../../schema/module';
import {
  ENTITY_TYPE_FINANCIAL_ACCOUNT,
  type StoreEntityFinancialAccount,
} from './financialData-types';
import {
  financialAccountResolvers,
} from './financialData-resolver';
import { NAME_FIELD, normalizeName } from '../../schema/identifier';
import type {
  StixFinancialAccount,
} from '../../types/stix-sdo';
import {
  convertFinancialAccountToStix,
} from '../../database/stix-converter';

interface Balance {
  as_of_date: object | string | null
  balance: number | null
}
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

registerDefinition(FINANCIAL_ACCOUNT_DEFINITION);
