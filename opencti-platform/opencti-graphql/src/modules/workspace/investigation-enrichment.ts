import type { AuthContext, AuthUser } from '../../types/user';
import { internalFindByIds, storeLoadById } from '../../database/middleware-loader';
import { AccessOperation, isUserHasCapability, KNOWLEDGE_KNENRICHMENT, validateUserAccessOperation } from '../../utils/access';
import { ForbiddenAccess, FunctionalError } from '../../config/errors';
import { type BasicStoreEntityWorkspace, ENTITY_TYPE_WORKSPACE } from './workspace-types';
import { findWorkPaginated } from '../../domain/work';
import { emptyPaginationResult } from '../../database/utils';
import { addFilter } from '../../utils/filtering/filtering-utils';
import type { WorkspaceEnrichmentWorksArgs } from '../../generated/graphql';
import type { BasicStoreBase } from '../../types/store';
import { ABSTRACT_STIX_OBJECT, ABSTRACT_STIX_RELATIONSHIP } from '../../schema/general';

const INVESTIGATION_UPDATE_CAPABILITY = 'INVESTIGATION_INUPDATE';

/**
 * Tagging an enrichment with an investigation requires to be allowed to edit that investigation.
 * A non member of a restricted investigation cannot load it, so it is reported as not found.
 * Capabilities are checked before the load so that the error does not reveal whether the id exists.
 */
export const validateEnrichmentInvestigation = async (
  context: AuthContext,
  user: AuthUser,
  investigationId: string,
  opts: { checkEnrichmentCapability?: boolean } = {},
) => {
  if (
    (opts.checkEnrichmentCapability && !isUserHasCapability(user, KNOWLEDGE_KNENRICHMENT))
    || !isUserHasCapability(user, INVESTIGATION_UPDATE_CAPABILITY)
  ) {
    throw ForbiddenAccess();
  }
  const investigation = await storeLoadById<BasicStoreEntityWorkspace>(context, user, investigationId, ENTITY_TYPE_WORKSPACE);
  if (!investigation || investigation.type !== 'investigation') {
    throw FunctionalError('Investigation not found', { investigationId });
  }
  if (!validateUserAccessOperation(user, investigation, AccessOperation.EDIT)) {
    throw ForbiddenAccess();
  }
  return investigation;
};

/**
 * The caller filters are nested under a top level AND with the investigation filter:
 * they can narrow the result, never reach works of another investigation.
 * A workspace that is not an investigation has no enrichment works.
 * Only the works of the entities of the investigation are returned, or of the given entityIds among them,
 * matched on their current standard id: like the entity jobs, the works of an entity merged into another one or whose
 * standard id changed are not found, nor those of an entity removed from the investigation.
 * The entities are loaded as the reader, so that the works of entities hidden by markings or organization sharing
 * (or deleted) are filtered before the pagination: they are not counted in the pageInfo either.
 */
export const findInvestigationEnrichmentWorks = async (
  context: AuthContext,
  user: AuthUser,
  workspace: BasicStoreEntityWorkspace,
  args: WorkspaceEnrichmentWorksArgs,
) => {
  if (workspace.type !== 'investigation') {
    return emptyPaginationResult();
  }
  const { entityIds, ...paginationArgs } = args;
  const investigatedIds = new Set(workspace.investigated_entities_ids ?? []);
  const entities = await internalFindByIds(
    context,
    user,
    entityIds ?? [...investigatedIds],
    { type: [ABSTRACT_STIX_OBJECT, ABSTRACT_STIX_RELATIONSHIP], baseData: true },
  ) as BasicStoreBase[];
  // An enrichment work stores the standard id of its entity, as matched by the entity jobs
  const standardIds = entities
    .filter((entity) => investigatedIds.has(entity.internal_id))
    .map((entity) => entity.standard_id);
  if (standardIds.length === 0) {
    return emptyPaginationResult();
  }
  const filters = addFilter(
    addFilter(args.filters, 'investigation_id', workspace.id),
    'event_source_id',
    standardIds,
  );
  return findWorkPaginated(context, user, { ...paginationArgs, filters });
};
