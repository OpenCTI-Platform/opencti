import { isDateNumericOrBooleanAttribute, schemaAttributesDefinition } from '../schema/schema-attributes';
import { FunctionalError, UnsupportedError } from '../config/errors';
import { getPirWithAccessCheck } from '../modules/pir/pir-checkPirAccess';
import type { AuthContext, AuthUser } from '../types/user';

const PIR_ORDERING_CRITERIA = ['pir_score', 'last_pir_score_date'];

export const buildElasticSortingForAttributeCriteria = async (
  context: AuthContext,
  user: AuthUser,
  orderCriteria: string,
  orderMode: 'asc' | 'desc' | null,
  pirId?: string | null,
) => {
  let definition;
  if (PIR_ORDERING_CRITERIA.includes(orderCriteria)) {
    // the pir id should be specified and the pir accessible
    if (!pirId) {
      throw FunctionalError('You should provide a PIR ID to order by pir_score.');
    }
    // check the user has access to the PIR
    await getPirWithAccessCheck(context, user, pirId);
    // return nested order criteria associated to the given PIR ID
    return { [`pir_information.${orderCriteria}`]: {
      order: orderMode,
      missing: '_last',
      nested: {
        path: 'pir_information',
        filter: {
          term: {
            'pir_information.pir_id.keyword': pirId,
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
