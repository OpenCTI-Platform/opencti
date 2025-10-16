import type { AuthContext, AuthUser } from '../../types/user';
import { checkEnterpriseEdition } from '../../enterprise-edition/ee';
import { ABSTRACT_STIX_OBJECT } from '../../schema/general';
import { storeLoadById } from '../../database/middleware-loader';
import { logApp } from '../../config/conf';
import type { EditInput, PatchMetricInput } from '../../generated/graphql';
import { updateAttribute } from '../../database/middleware';
import { UnknownError } from '../../config/errors';

export const patchMetric = async (context: AuthContext, user: AuthUser, entityId: string, input: PatchMetricInput) => {
  await checkEnterpriseEdition(context);
  const entity = await storeLoadById(context, user, entityId, ABSTRACT_STIX_OBJECT);
  if (!entity) {
    throw UnknownError('The entity cannot be found', { entityId });
  }
  logApp.info(`Updating metrics on ${entity.id}`, input);
  // TODO Check that this metric is allowed on this entity from configuration

  // We take all but the one in parameters
  const metrics = entity.metrics?.filter((existingMetric) => existingMetric.name !== input.name) || [];
  metrics.push({ name: input.name, value: input.value });
  const patch: EditInput[] = [{ key: 'metrics', value: metrics }];
  logApp.info(`Patch ready ${entity.id}`, patch);
  const { element } = await updateAttribute(context, user, entity.id, entity.type, patch);
  return element.metrics;
};

export const getEntityMetricsConfiguration = () => {
  // TODO take from yaml/env
  return [{ entity_type: 'Organization', metrics: ['number_of_validated_reports'] }];
};
