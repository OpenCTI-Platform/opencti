import type { AuthContext, AuthUser } from '../../types/user';
import { checkEnterpriseEdition } from '../../enterprise-edition/ee';
import { ABSTRACT_BASIC_OBJECT } from '../../schema/general';
import { storeLoadById } from '../../database/middleware-loader';
import { logApp } from '../../config/conf';
import type { EditInput, PatchMetricInput } from '../../generated/graphql';
import { updateAttribute } from '../../database/middleware';
import { UnknownError } from '../../config/errors';

export const patchMetric = async (context: AuthContext, user: AuthUser, entityId: string, input: PatchMetricInput) => {
  await checkEnterpriseEdition(context);

  const entity = await storeLoadById(context, user, entityId, ABSTRACT_BASIC_OBJECT);
  if (!entity) {
    throw UnknownError('The entity cannot be found', { entityId });
  }
  logApp.info(`Updating metrics on ${entity.id}`, input);
  // TODO Check that this metric is allowed on this entity from configuration

  // TODO one day use path to replace only required
  //  for now throw not implemented + check config mono metric
  // We take all but the one in parameters
  const metrics = entity.metrics?.filter((existingMetric) => existingMetric.name !== input.name) || [];
  metrics.push({ name: input.name, value: input.value });
  const patch: EditInput[] = [{ key: 'metrics', value: metrics }];
  logApp.info(`Patch ready ${entity.id}`, patch);
  const { element } = await updateAttribute(context, user, entity.id, entity.type, patch);
  return element.metrics;
};
