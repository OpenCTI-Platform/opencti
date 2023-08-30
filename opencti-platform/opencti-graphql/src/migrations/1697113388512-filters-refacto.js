import { head, last, toPairs } from 'ramda';
import { executionContext, SYSTEM_USER } from '../utils/access';
import { listAllEntities } from '../database/middleware-loader';
import {
  ENTITY_TYPE_FEED,
  ENTITY_TYPE_STREAM_COLLECTION,
  ENTITY_TYPE_TAXII_COLLECTION
} from '../schema/internalObject';
import { ENTITY_TYPE_TRIGGER } from '../modules/notification/notification-types';
import { logApp } from '../config/conf';
import { updateAttribute } from '../database/middleware';
import { UPDATE_OPERATION_REPLACE } from '../database/utils';

const message = '[MIGRATION] Stored filters refacto';

export const up = async (next) => {
  logApp.info(`${message} > started`);
  const context = executionContext('migration', SYSTEM_USER);

  // fetch entities with stored filters
  const entitiesToRefacto = await listAllEntities(
    context,
    SYSTEM_USER,
    [ENTITY_TYPE_STREAM_COLLECTION, ENTITY_TYPE_FEED, ENTITY_TYPE_TAXII_COLLECTION, ENTITY_TYPE_TRIGGER],
  );

  const filterKeysConvertor = new Map([
    ['labelledBy', 'objectLabel'],
    ['markedBy', 'objectMarking'],
    ['objectContains', 'objects'],
    ['killChainPhase', 'killChainPhases'],
    ['assigneeTo', 'objectAssignee'],
    ['participant', 'objectParticipant'],
    ['creator', 'creator_id'],
  ]);
  const convertFilters = (filters) => {
    const newFiltersContent = toPairs(JSON.parse(filters))
      .map((pair) => {
        let key = head(pair);
        let operator = 'eq';
        let mode = 'or';
        if (key.endsWith('start_date') || key.endsWith('_gt')) {
          key = key.replace('_start_date', '').replace('_gt', '');
          operator = 'gt';
        } else if (key.endsWith('end_date') || key.endsWith('_lt')) {
          key = key.replace('_end_date', '').replace('_lt', '');
          operator = 'lt';
        } else if (key.endsWith('_lte')) {
          key = key.replace('_lte', '');
          operator = 'lte';
        } else if (key.endsWith('_not_eq')) {
          key = key.replace('_not_eq', '');
          operator = 'not_eq';
          mode = 'and';
        }
        if (filterKeysConvertor.has(key)) {
          key = filterKeysConvertor.get(key);
        }
        const values = last(pair);
        const valIds = values.map((v) => v.id);
        return { key, values: valIds, operator, mode };
      });
    return {
      mode: 'and',
      filters: newFiltersContent,
      filterGroups: [],
    };
  };

  const filtersRefactoPromises = entitiesToRefacto.map((entity) => {
    const finalFilters = convertFilters(entity.filters);
    const input = {
      key: 'filters',
      value: [JSON.stringify(finalFilters)],
      operation: UPDATE_OPERATION_REPLACE,
    };
    return updateAttribute(context, context.user, entity.id, entity.entity_type, input);
  });
  await Promise.all(filtersRefactoPromises);

  logApp.info(`${message} > done`);
  next();
};

export const down = async (next) => {
  next();
};
