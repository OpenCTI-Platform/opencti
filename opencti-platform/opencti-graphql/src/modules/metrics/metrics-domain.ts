import type { AuthContext, AuthUser } from '../../types/user';
import { checkEnterpriseEdition } from '../../enterprise-edition/ee';
import { ABSTRACT_BASIC_OBJECT } from '../../schema/general';
import { storeLoadById } from '../../database/middleware-loader';
import type { EditInput, PatchMetricInput } from '../../generated/graphql';
import { updateAttribute } from '../../database/middleware';
import { UnknownError } from '../../config/errors';
import { getEntityMetricsConfiguration } from './metrics-utils';

export const patchMetric = async (context: AuthContext, user: AuthUser, entityId: string, input: PatchMetricInput) => {
  await checkEnterpriseEdition(context);

  const entity = await storeLoadById(context, user, entityId, ABSTRACT_BASIC_OBJECT);
  if (!entity) {
    throw UnknownError('The entity cannot be found', { entityId });
  }

  const allKnownAttributes = getEntityMetricsConfiguration();
  // metricDefinition is in env var or json, it's all lower case there, comparison must not be case-sensitive
  const entityConfiguration = allKnownAttributes.find((metricDefinition) => metricDefinition.entity_type.toLowerCase() === entity.entity_type.toLowerCase());
  if (!entityConfiguration) {
    throw UnknownError('The metric entity is not allowed', { name: input.name, entityId, entityType: entity.entity_type });
  }
  if (!entityConfiguration.metrics.some((metricDescription) => metricDescription.attribute === input.name)) {
    throw UnknownError('The metric name is not allowed', { name: input.name, entityId });
  }

  // TODO one day use path to replace only required + manage lock on updates.
  //  for now throw not implemented + check config mono metric
  // We take all but the one in parameters
  const metrics = entity.metrics?.filter((existingMetric) => existingMetric.name !== input.name) || [];
  metrics.push({ name: input.name, value: input.value });
  const patch: EditInput[] = [{ key: 'metrics', value: metrics }];
  const { element } = await updateAttribute(context, user, entity.id, entity.entity_type, patch);
  return element;
};
