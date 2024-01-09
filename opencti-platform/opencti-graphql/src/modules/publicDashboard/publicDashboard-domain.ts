import { v4 as uuidv4 } from 'uuid';
import type { AuthContext, AuthUser } from '../../types/user';
import { listEntitiesPaginated, storeLoadById } from '../../database/middleware-loader';
import { ENTITY_TYPE_PUBLIC_DASHBOARD, type BasicStoreEntityPublicDashboard } from './publicDashboard-types';
import { createEntity, deleteElementById, loadEntity, updateAttribute } from '../../database/middleware';
import { type BasicStoreEntityWorkspace, ENTITY_TYPE_WORKSPACE } from '../workspace/workspace-types';
import { fromBase64, isNotEmptyField, toBase64 } from '../../database/utils';
import { notify } from '../../database/redis';
import { BUS_TOPICS } from '../../config/conf';
import type { EditInput, FilterGroup, PublicDashboardAddInput, QueryPublicDashboardsArgs } from '../../generated/graphql';
import { FunctionalError } from '../../config/errors';
import { SYSTEM_USER } from '../../utils/access';

export const findById = (
  context: AuthContext,
  user: AuthUser,
  id: string,
) => {
  return storeLoadById<BasicStoreEntityPublicDashboard>(
    context,
    user,
    id,
    ENTITY_TYPE_PUBLIC_DASHBOARD,
  );
};

export const findAll = (
  context: AuthContext,
  user: AuthUser,
  args: QueryPublicDashboardsArgs,
) => {
  return listEntitiesPaginated<BasicStoreEntityPublicDashboard>(
    context,
    user,
    [ENTITY_TYPE_PUBLIC_DASHBOARD],
    args,
  );
};

export const getPublicDashboard = (
  context: AuthContext,
  uri_key: string,
) => {
  return loadEntity(
    context,
    SYSTEM_USER,
    [ENTITY_TYPE_PUBLIC_DASHBOARD],
    {
      filters: {
        mode: 'and',
        filters: [
          { key: ['uri_key'], values: [uri_key], mode: 'or', operator: 'eq' }
        ],
        filterGroups: [],
      } as FilterGroup
    }
  ) as Promise<BasicStoreEntityPublicDashboard>;
};

export const addPublicDashboard = async (
  context: AuthContext,
  user: AuthUser,
  input: PublicDashboardAddInput,
) => {
  // Get private dashboard manifest
  const dashboard: BasicStoreEntityWorkspace = await storeLoadById(
    context,
    user,
    input.dashboard_id,
    ENTITY_TYPE_WORKSPACE,
  );
  if (!dashboard.manifest) {
    throw FunctionalError('Cannot published empty dashboard');
  }

  const parsedManifest = JSON.parse(fromBase64(dashboard.manifest) ?? '{}');
  // Removing the "dataSelection" key
  if (parsedManifest && isNotEmptyField(parsedManifest.widgets)) {
    Object.keys(parsedManifest.widgets).forEach((widgetId) => {
      delete parsedManifest.widgets[widgetId].dataSelection;
    });
  }

  // Create public manifest
  const publicManifest = toBase64(JSON.stringify(parsedManifest) ?? '{}');

  // Create publicDashboard
  const publicDashboardToCreate = { // TODO add marking max to input
    name: input.name,
    description: input.description,
    public_manifest: publicManifest,
    private_manifest: dashboard.manifest,
    user_id: user.id,
    uri_key: uuidv4(),
  };

  const created = await createEntity(
    context,
    user,
    publicDashboardToCreate,
    ENTITY_TYPE_PUBLIC_DASHBOARD,
  );
  return notify(BUS_TOPICS[ENTITY_TYPE_PUBLIC_DASHBOARD].ADDED_TOPIC, created, user);
};

export const publicDashboardEditField = async (
  context: AuthContext,
  user: AuthUser,
  id: string,
  input: EditInput[],
) => {
  const { element } = await updateAttribute(
    context,
    user,
    id,
    ENTITY_TYPE_PUBLIC_DASHBOARD,
    input,
  );
  return notify(BUS_TOPICS[ENTITY_TYPE_PUBLIC_DASHBOARD].EDIT_TOPIC, element, user);
};

export const publicDashboardDelete = async (context: AuthContext, user: AuthUser, id: string) => {
  const element = await deleteElementById(
    context,
    user,
    id,
    ENTITY_TYPE_PUBLIC_DASHBOARD
  );
  return notify(BUS_TOPICS[ENTITY_TYPE_PUBLIC_DASHBOARD].DELETE_TOPIC, element, user).then(() => id);
};
