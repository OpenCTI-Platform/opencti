import { SemanticAttributes } from '@opentelemetry/semantic-conventions';
import type { AuthContext, AuthUser } from '../../types/user';
import { listAllEntities, storeLoadById } from '../../database/middleware-loader';
import { createEntity, loadEntity, patchAttribute, updateAttribute } from '../../database/middleware';
import { getEntitiesListFromCache } from '../../database/cache';
import { telemetry } from '../../config/tracing';
import {
  type BasicStoreEntityManagerConfiguration,
  ENTITY_TYPE_MANAGER_CONFIGURATION
} from './managerConfiguration-types';
import type { EditInput, FilterGroup } from '../../generated/graphql';
import { publishUserAction } from '../../listener/UserActionListener';
import { notify } from '../../database/redis';
import conf, { BUS_TOPICS } from '../../config/conf';

export const findById = async (context: AuthContext, user: AuthUser, id: string): Promise<BasicStoreEntityManagerConfiguration> => {
  return storeLoadById(context, user, id, ENTITY_TYPE_MANAGER_CONFIGURATION);
};

export const findByManagerId = async (context: AuthContext, user: AuthUser, managerId: string): Promise<BasicStoreEntityManagerConfiguration> => {
  const findByTypeFn = async () => {
    return loadEntity(context, user, [ENTITY_TYPE_MANAGER_CONFIGURATION], {
      filters: {
        mode: 'and',
        filters: [
          { key: ['manager_id'], values: [managerId], mode: 'or', operator: 'eq' }
        ],
        filterGroups: [],
      } as FilterGroup
    });
  };
  return telemetry(context, user, 'QUERY managerConfiguration', {
    [SemanticAttributes.DB_NAME]: 'managerConfiguration_domain',
    [SemanticAttributes.DB_OPERATION]: 'read',
  }, findByTypeFn);
};

export const getManagerSettings = async (managerId: string) => {
  return conf.get(managerId.toLowerCase());
};

export const managerConfigurationEditField = async (context: AuthContext, user: AuthUser, id: string, input: EditInput[]) => {
  const { element } = await updateAttribute(context, user, id, ENTITY_TYPE_MANAGER_CONFIGURATION, input);
  await publishUserAction({
    user,
    event_type: 'mutation',
    event_scope: 'update',
    event_access: 'administration',
    message: `updates \`${input.map((i) => i.key).join(', ')}\` for manager configuration \`${element.manager_id}\``,
    context_data: { id, entity_type: ENTITY_TYPE_MANAGER_CONFIGURATION, input }
  });
  return notify(BUS_TOPICS[ENTITY_TYPE_MANAGER_CONFIGURATION].EDIT_TOPIC, element, user);
};

export const getManagerConfigurationFromCache = async (context: AuthContext, user: AuthUser, managerId: string): Promise<BasicStoreEntityManagerConfiguration | undefined> => {
  const managerConfigurations = await getEntitiesListFromCache<BasicStoreEntityManagerConfiguration>(context, user, ENTITY_TYPE_MANAGER_CONFIGURATION);
  return managerConfigurations.find((m) => m.manager_id === managerId);
};

export const updateManagerConfigurationLastRun = async (
  context: AuthContext,
  user: AuthUser,
  managerConfigurationId: string,
  updateInput: { last_run_start_date: Date, last_run_end_date: Date }
) => {
  const updatedManagerConfiguration = await patchAttribute(context, user, managerConfigurationId, ENTITY_TYPE_MANAGER_CONFIGURATION, updateInput);
  await notify(BUS_TOPICS[ENTITY_TYPE_MANAGER_CONFIGURATION].EDIT_TOPIC, updatedManagerConfiguration, user);
};

// -- INITIALIZATION --

const addManagerConfiguration = async (
  context: AuthContext,
  user: AuthUser,
  managerConfiguration: { manager_id: string, manager_running: boolean }
) => {
  const createdManagerConfiguration = await createEntity(context, user, managerConfiguration, ENTITY_TYPE_MANAGER_CONFIGURATION);
  await notify(BUS_TOPICS[ENTITY_TYPE_MANAGER_CONFIGURATION].ADDED_TOPIC, createdManagerConfiguration, user);
};

export const initiManagerConfigurations = async (context: AuthContext, user: AuthUser) => {
  const managerConfigurations = await listAllEntities<BasicStoreEntityManagerConfiguration>(context, user, [ENTITY_TYPE_MANAGER_CONFIGURATION], { connectionFormat: false });
  const managers = ['FILE_INDEX_MANAGER'];
  for (let index = 0; index < managers.length; index += 1) {
    const managerId = managers[index];
    const managerConfigurationExist = managerConfigurations.some((m) => m.manager_id === managerId);
    if (!managerConfigurationExist) {
      const managerConfiguration = {
        manager_id: managerId,
        manager_running: false,
      };
      await addManagerConfiguration(context, user, managerConfiguration);
    }
  }
};
