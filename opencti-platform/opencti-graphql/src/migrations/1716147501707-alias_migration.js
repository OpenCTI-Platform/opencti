import { logApp } from '../config/conf';
import { BULK_TIMEOUT, elBulk, elList } from '../database/engine';
import { executionContext, SYSTEM_USER } from '../utils/access';
import { READ_DATA_INDICES } from '../database/utils';
import { aliases, iAliasedIds, xOpenctiAliases } from '../schema/attribute-definition';
import { FilterOperator } from '../generated/graphql';
import { generateAliasesIdsForInstance } from '../schema/identifier';

const message = '[MIGRATION] Alias ids rewrite to align on algorithm modification';

export const up = async (next) => {
  const context = executionContext('migration');
  logApp.info(`${message} > started`);
  const callback = async (entities) => {
    const bulkOperations = entities.map((entity) => {
      const aliasIds = generateAliasesIdsForInstance(entity);
      return [
        { update: { _index: entity._index, _id: entity.id } },
        { doc: { [iAliasedIds.name]: aliasIds } },
      ];
    }).flat();
    await elBulk({ refresh: true, timeout: BULK_TIMEOUT, body: bulkOperations });
  };
  const filters = {
    mode: 'or',
    filters: [
      { key: xOpenctiAliases.name, values: [], operator: FilterOperator.NotNil },
      { key: aliases.name, values: [], operator: FilterOperator.NotNil }
    ],
    filterGroups: [],
  };
  const opts = { filters, noFiltersChecking: true, callback };
  await elList(context, SYSTEM_USER, READ_DATA_INDICES, opts);

  logApp.info(`${message} > done`);
  next();
};

export const down = async (next) => {
  next();
};
