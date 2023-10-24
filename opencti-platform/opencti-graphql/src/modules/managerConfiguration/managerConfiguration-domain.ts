import { SemanticAttributes } from '@opentelemetry/semantic-conventions';
import type { AuthContext, AuthUser } from '../../types/user';
import { storeLoadById } from '../../database/middleware-loader';
import { loadEntity, updateAttribute } from '../../database/middleware';
import { telemetry } from '../../config/tracing';
import {
  type BasicStoreEntityManagerConfiguration,
  ENTITY_TYPE_MANAGER_CONFIGURATION
} from './managerConfiguration-types';
import type { EditInput } from '../../generated/graphql';
import { publishUserAction } from '../../listener/UserActionListener';
import { notify } from '../../database/redis';
import { BUS_TOPICS } from '../../config/conf';

export const findById = async (context: AuthContext, user: AuthUser, id: string): Promise<BasicStoreEntityManagerConfiguration> => {
  return storeLoadById(context, user, id, ENTITY_TYPE_MANAGER_CONFIGURATION);
};

export const findByManagerId = async (context: AuthContext, user: AuthUser, managerId: string): Promise<BasicStoreEntityManagerConfiguration> => {
  const findByTypeFn = async () => {
    return loadEntity(context, user, [ENTITY_TYPE_MANAGER_CONFIGURATION], {
      filters: [{ key: 'manager_id', values: [managerId] }]
    });
  };
  return telemetry(context, user, 'QUERY managerConfiguration', {
    [SemanticAttributes.DB_NAME]: 'managerConfiguration_domain',
    [SemanticAttributes.DB_OPERATION]: 'read',
  }, findByTypeFn);
};

export const managerConfigurationEditField = async (context: AuthContext, user: AuthUser, id: string, input: EditInput[]) => {
  const { element } = await updateAttribute(context, user, id, ENTITY_TYPE_MANAGER_CONFIGURATION, input);
  await publishUserAction({
    user,
    event_type: 'mutation',
    event_scope: 'update',
    event_access: 'administration',
    message: `updates \`${input.map((i) => i.key).join(', ')}\` for entity setting \`${element.manager_id}\``,
    context_data: { id, entity_type: element.manager_id, input }
  });
  return notify(BUS_TOPICS[ENTITY_TYPE_MANAGER_CONFIGURATION].EDIT_TOPIC, element, user);
};
