import { isDateNumericOrBooleanAttribute, schemaAttributesDefinition } from '../schema/schema-attributes';
import { FunctionalError, UnsupportedError } from '../config/errors';

const PIR_SCORE_ORDERING_PREFIX = 'pir_score';

export const buildElasticSortingForAttributeCriteria = (orderCriteria: string, orderMode: 'asc' | 'desc') => {
  let definition;
  if (orderCriteria.startsWith(PIR_SCORE_ORDERING_PREFIX)) {
    // the key should be of format: pir_score.PIR_ID
    const splittedCriteria = orderCriteria.split('.');
    if (splittedCriteria.length !== 2) {
      throw FunctionalError('The pir_score ordering criteria should be followed by a dot and the pir ID', { orderCriteria });
    }
    const pirId = splittedCriteria[1];
    // return nested pir_score order criteria associated to the given PIR ID
    return { 'pir_scores.pir_score': {
      order: orderMode,
      missing: '_last',
      nested: {
        path: 'pir_scores',
        filter: {
          term: {
            'pir_scores.pir_id.keyword': pirId,
          },
        }
      }
    } };
  }
  if (orderCriteria.includes('.') && !orderCriteria.endsWith('*')) {
    const attribute = schemaAttributesDefinition.getAttributeByName(orderCriteria.split('.')[0]);
    if (attribute && attribute.type === 'object' && attribute.format === 'standard') {
      definition = schemaAttributesDefinition.getAttributeMappingFromPath(orderCriteria);
    } else {
      definition = schemaAttributesDefinition.getAttributeByName(orderCriteria);
    }
  } else {
    definition = schemaAttributesDefinition.getAttributeByName(orderCriteria);
  }

  // criteria not in schema, attempt keyword sorting as a last resort
  if (!definition) {
    return { [`${orderCriteria}.keyword`]: { order: orderMode, missing: '_last' } };
  }

  if (isDateNumericOrBooleanAttribute(orderCriteria)) {
    // sorting on null dates results to an error, one way to fix it is to use missing: 0
    // see https://github.com/elastic/elasticsearch/issues/81960
    return { [orderCriteria]: { order: orderMode, missing: definition.type === 'date' ? 0 : '_last' } };
  }

  // for sorting by object attribute, we need the sortBy def to know which internal mapping to use
  if (definition.type === 'object' && (definition.format === 'standard' || definition.format === 'nested')) {
    const { sortBy } = definition;
    if (sortBy) {
      if (sortBy.type === 'numeric' || sortBy.type === 'boolean' || sortBy.type === 'date') {
        return { [sortBy.path]: {
          order: orderMode,
          missing: sortBy.type === 'date' ? 0 : '_last',
        } };
      }
      return { [`${sortBy.path}.keyword`]: {
        order: orderMode, missing: '_last',
      } };
    }
    throw UnsupportedError(`Sorting on [${orderCriteria}] is not supported: this criteria does not have a sortBy definition in schema`);
  }

  return { [`${orderCriteria}.keyword`]: { order: orderMode, missing: '_last' } };
};
