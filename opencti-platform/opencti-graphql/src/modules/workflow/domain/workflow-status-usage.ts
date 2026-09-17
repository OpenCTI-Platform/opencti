import { fullEntitiesList } from '../../../database/middleware-loader';
import { READ_INDEX_DRAFT_OBJECTS } from '../../../database/utils';
import { FilterMode } from '../../../generated/graphql';
import type { AuthContext, AuthUser } from '../../../types/user';

/**
 * Entities of `entityType` whose legacy `x_opencti_workflow_id` field points at `statusId`,
 * across the live index and every draft — a Status referenced only from within a draft still
 * counts, since publishing that draft later would leave it pointing at a removed status.
 *
 * Extracted to its own dependency-free module so both `workflow-domain.ts` and
 * `workflow-validation.ts` can use it without creating a circular import between the two.
 */
export const findEntitiesReferencingStatus = async (
  context: AuthContext,
  user: AuthUser,
  entityType: string,
  statusId: string,
): Promise<Array<{ id: string; entity_type: string }>> => {
  const statusFilters = {
    mode: FilterMode.And,
    filters: [{ key: ['x_opencti_workflow_id'], values: [statusId] }],
    filterGroups: [],
  };
  const liveEntities = await fullEntitiesList<any>(context, user, [entityType], { filters: statusFilters });
  const draftEntities = await fullEntitiesList<any>(context, user, [entityType], {
    indices: [READ_INDEX_DRAFT_OBJECTS],
    filters: statusFilters,
  });
  return [...liveEntities, ...draftEntities].map((entity) => ({ id: entity.id, entity_type: entityType }));
};

/**
 * True if any entity of `entityType` currently has its legacy `x_opencti_workflow_id` field
 * pointing at this `Status`, either in the live index or inside any draft (across all drafts,
 * not just one) — a `Status` referenced only from within a draft must not be deleted, since
 * publishing that draft later would leave it pointing at a hard-deleted record.
 */
export const isStatusReferencedByEntity = async (
  context: AuthContext,
  user: AuthUser,
  entityType: string,
  statusId: string,
): Promise<boolean> => {
  const statusFilters = {
    mode: FilterMode.And,
    filters: [{ key: ['x_opencti_workflow_id'], values: [statusId] }],
    filterGroups: [],
  };
  const entities = await fullEntitiesList<any>(context, user, [entityType], { filters: statusFilters });
  if (entities.length > 0) return true;

  const draftEntities = await fullEntitiesList<any>(context, user, [entityType], {
    indices: [READ_INDEX_DRAFT_OBJECTS],
    filters: statusFilters,
  });
  return draftEntities.length > 0;
};
