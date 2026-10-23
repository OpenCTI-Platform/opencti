import type { AuthContext, AuthUser } from '../../types/user';
import { internalFindByIdsMapped } from '../../database/middleware-loader';
import { elAggregationDistinctValues } from '../../database/engine';
import { AccessOperation, isUserHasCapability, KNOWLEDGE_KNENRICHMENT, validateUserAccessOperation } from '../../utils/access';
import { ForbiddenAccess } from '../../config/errors';
import type { BasicStoreEntityWorkspace } from './workspace-types';
import { findInvestigationById } from './workspace-domain';
import { findWorkPaginated } from '../../domain/work';
import { emptyPaginationResult, READ_INDEX_HISTORY } from '../../database/utils';
import { addFilter } from '../../utils/filtering/filtering-utils';
import type { WorkspaceEnrichmentWorksArgs } from '../../generated/graphql';
import { ABSTRACT_STIX_OBJECT, ABSTRACT_STIX_RELATIONSHIP } from '../../schema/general';
import { xOpenctiStixIds } from '../../schema/attribute-definition';
import { ENTITY_TYPE_WORK } from '../../schema/internalObject';

const INVESTIGATION_UPDATE_CAPABILITY = 'INVESTIGATION_INUPDATE';

/**
 * Tagging an enrichment with an investigation requires to be allowed to enrich and to edit that investigation.
 * The enrichment capability is checked here for every caller: the bulk enrichment tasks are not guarded by it otherwise.
 * A non member of a restricted investigation cannot load it, so it is reported as not found.
 * Capabilities are checked before the load so that the error does not reveal whether the id exists.
 */
export const validateEnrichmentInvestigation = async (
  context: AuthContext,
  user: AuthUser,
  investigationId: string,
) => {
  if (!isUserHasCapability(user, KNOWLEDGE_KNENRICHMENT) || !isUserHasCapability(user, INVESTIGATION_UPDATE_CAPABILITY)) {
    throw ForbiddenAccess();
  }
  const investigation = await findInvestigationById(context, user, investigationId);
  if (!validateUserAccessOperation(user, investigation, AccessOperation.EDIT)) {
    throw ForbiddenAccess();
  }
  return investigation;
};

/**
 * Retrieves the works of the enrichment connectors started from the given investigation.
 *
 * By default it returns the works of all the entities of the investigation, but a list of entity ids (internal
 * or standard) can be given: only the works of those entities, among the entities of the investigation, are returned.
 *
 * The distinct sources of the works (event_source_id) are first aggregated, then those sources are loaded as the user and
 * only the ones that are entities of the investigation (and of the selection) are kept. The final filter so holds at
 * most one id per enriched entity, instead of all the ids of all the entities of the investigation, which could
 * exceed the elastic terms limit on large investigations.
 *
 * Remark-1: a work stores in event_source_id the standard id its entity had when the enrichment started. The sources
 * are matched on all the stix ids of the entities (standard_id and x_opencti_stix_ids), so the works of an entity
 * merged into an entity of the investigation, or of an observable whose standard id was upgraded, are still found:
 * both keep the previous standard id in their stix ids. The renaming of a domain object does not keep its previous
 * standard id, nor does a merge update the entities of the investigation: those works are not found.
 *
 * Remark-2: the sources are loaded as the user, to benefit from our internal mechanisms of markings, organization
 * sharing, etc.: a work concerning an entity the user cannot see is filtered before the pagination, so it is neither
 * returned nor counted in the pageInfo.
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
  const investigationFilters = addFilter(args.filters, 'investigation_id', workspace.id);

  // 01. Collect the distinct sources of the works of the investigation, without reading the works
  const sourceIds = await elAggregationDistinctValues(
    context,
    user,
    READ_INDEX_HISTORY,
    'event_source_id.keyword',
    { types: [ENTITY_TYPE_WORK], filters: investigationFilters },
  );
  if (sourceIds.length === 0) {
    return emptyPaginationResult();
  }

  // 02. Load the sources as the user, keyed by all their ids (see Remark-1)
  const sources = await internalFindByIdsMapped(
    context,
    user,
    sourceIds,
    {
      type: [ABSTRACT_STIX_OBJECT, ABSTRACT_STIX_RELATIONSHIP],
      baseData: true,
      baseFields: [xOpenctiStixIds.name],
      mapWithAllIds: true,
    },
  );

  // 03. Keep the sources that are entities of the investigation, and of the selection when given
  const investigatedIds = new Set(workspace.investigated_entities_ids ?? []);
  const selectedIds = entityIds ? new Set(entityIds) : undefined;
  const allowedSourceIds = sourceIds.filter((sourceId) => {
    const entity = sources[sourceId];
    return !!entity
      && investigatedIds.has(entity.internal_id)
      && (!selectedIds || selectedIds.has(entity.internal_id) || selectedIds.has(entity.standard_id));
  });
  if (allowedSourceIds.length === 0) {
    return emptyPaginationResult();
  }

  // 04. Paginate the works of the kept sources only
  const filters = addFilter(investigationFilters, 'event_source_id', allowedSourceIds);
  return findWorkPaginated(context, user, { ...paginationArgs, filters });
};
