import { logApp } from '../config/conf';
import { BULK_TIMEOUT, elBulk, elCount, elList } from '../database/engine';
import { executionContext, SYSTEM_USER } from '../utils/access';
import { READ_DATA_INDICES, READ_DATA_INDICES_WITHOUT_INTERNAL_WITHOUT_INFERRED } from '../database/utils';
import { iAliasedIds } from '../schema/attribute-definition';
import { FilterOperator } from '../generated/graphql';
import { generateAliasesIdsForInstance } from '../schema/identifier';

const message = '[MIGRATION] Alias ids rewrite to align on algorithm modification';

export const up = async (next) => {
  const context = executionContext('migration');
  const filters = {
    mode: 'or',
    filters: [{ key: iAliasedIds.name, values: [], operator: FilterOperator.NotNil }],
    filterGroups: [],
  };
  const total = await elCount(context, SYSTEM_USER, READ_DATA_INDICES, { filters, noFiltersChecking: true });
  logApp.info(`${message} > started, ${total} elements to modify`);
  let totalIndex = 0;
  const callback = async (entities) => {
    totalIndex += entities.length;
    const bulkOperations = entities.map((entity) => {
      const aliasIds = generateAliasesIdsForInstance(entity);
      return [
        { update: { _index: entity._index, _id: entity.id } },
        { doc: { [iAliasedIds.name]: aliasIds } },
      ];
    }).flat();
    await elBulk({ refresh: true, timeout: BULK_TIMEOUT, body: bulkOperations });
    logApp.info(`${message} > progress, ${totalIndex}/${total}`);
  };

  await elList(context, SYSTEM_USER, READ_DATA_INDICES_WITHOUT_INTERNAL_WITHOUT_INFERRED, { filters, noFiltersChecking: true, callback });
  logApp.info(`${message} > done`);
  next();
};

export const down = async (next) => {
  next();
};
