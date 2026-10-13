import type { AuthContext, AuthUser } from '../../types/user';
import { internalFindByIdsMapped, storeLoadById } from '../../database/middleware-loader';
import { AccessOperation, isUserHasCapability, KNOWLEDGE_KNENRICHMENT, validateUserAccessOperation } from '../../utils/access';
import { ForbiddenAccess, FunctionalError } from '../../config/errors';
import { type BasicStoreEntityWorkspace, ENTITY_TYPE_WORKSPACE } from './workspace-types';
import { findWorkPaginated } from '../../domain/work';
import { emptyPaginationResult, isNotEmptyField } from '../../database/utils';
import { addFilter } from '../../utils/filtering/filtering-utils';
import type { WorkspaceEnrichmentWorksArgs } from '../../generated/graphql';
import type { BasicConnection, BasicStoreBase } from '../../types/store';

type EnrichmentWork = BasicStoreBase & { event_source_id?: string };

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
 * Access to the workspace is checked when it is loaded. On top of that, a work is only returned when
 * the reader can load its enriched entity (event_source_id): an investigation reader must not learn about
 * enrichments of entities hidden by markings or organization sharing (nor of deleted entities).
 * Works without an event_source_id are kept. Filtering happens after pagination, with one batched
 * lookup per page: a page can come back shorter than `first`, and its pageInfo is the one of the underlying page.
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
  const page = await findWorkPaginated(
    context,
    user,
    { ...args, filters: addFilter(args.filters, 'investigation_id', workspace.id) },
  ) as BasicConnection<EnrichmentWork>;
  const sourceIds = Array.from(new Set(page.edges.map((edge) => edge.node.event_source_id).filter(isNotEmptyField)));
  if (sourceIds.length === 0) {
    return page;
  }
  // event_source_id is the standard id of the enriched entity at enrichment time: match it on every id of the entities
  const readable = await internalFindByIdsMapped(
    context,
    user,
    sourceIds,
    { mapWithAllIds: true, baseData: true, baseFields: ['x_opencti_stix_ids'] },
  );
  const edges = page.edges.filter((edge) => !edge.node.event_source_id || readable[edge.node.event_source_id]);
  return { ...page, edges };
};
