import * as R from 'ramda';
import { isEmptyField } from '../../database/utils';
import { AUTOMATION_MANAGER_USER, executionContext, isInternalUser } from '../../utils/access';
import { getEntitiesListFromCache } from '../../database/cache';
import type { AuthContext, AuthUser } from '../../types/user';
import { ENTITY_TYPE_USER } from '../../schema/internalObject';
import type { StixBundle, StixObject } from '../../types/stix-2-1-common';
import { STIX_EXT_OCTI } from '../../types/stix-2-1-extensions';
import { FunctionalError } from '../../config/errors';
import { ENTITY_TYPE_IDENTITY_ORGANIZATION } from '../organization/organization-types';
import type { FilterGroup, PlaybookAddNodeInput } from '../../generated/graphql';
import { PLAYBOOK_INTERNAL_DATA_CRON } from './playbook-components';
import { elFindByIds } from '../../database/engine';
import { checkAndConvertFilters, type FiltersIdsFinder } from '../../utils/filtering/filtering-utils';
import { validateFilterGroupForStixMatch } from '../../utils/filtering/filtering-stix/stix-filtering';
import type { ComponentDefinition, LinkDefinition, NodeDefinition } from './playbook-types';
import { logApp } from '../../config/conf';

export const extractBundleBaseElement = (instanceId: string, bundle: StixBundle): StixObject => {
  const baseData = bundle.objects.find((o) => o.id === instanceId);
  if (!baseData) throw FunctionalError('Playbook base element no longer accessible');
  return baseData;
};

/**
 * Returns the list of all users authorized based on given members array.
 *
 * @param members Array of members.
 * @param baseData Data from event.
 * @param bundle Stix bundle transiting through playbook components.
 * @returns List of users.
 */
export const convertMembersToUsers = async (
  members: { value: string }[],
  baseData: StixObject,
  bundle: StixBundle,
) => {
  if (isEmptyField(members)) return [];
  const platformUsers = await getEntitiesListFromCache<AuthUser>(
    executionContext('playbook_components'),
    AUTOMATION_MANAGER_USER,
    ENTITY_TYPE_USER,
  );

  const membersIds: string[] = [];
  members?.forEach((m) => {
    if (m.value === 'AUTHOR') {
      membersIds.push(baseData.extensions[STIX_EXT_OCTI].created_by_ref_id);
    } else if (m.value === 'CREATORS') {
      const creatorIds = baseData.extensions[STIX_EXT_OCTI].creator_ids;
      membersIds.push(...creatorIds);
    } else if (m.value === 'ASSIGNEES') {
      const assigneeIds = baseData.extensions[STIX_EXT_OCTI].assignee_ids;
      membersIds.push(...assigneeIds);
    } else if (m.value === 'PARTICIPANTS') {
      const participantIds = baseData.extensions[STIX_EXT_OCTI].participant_ids;
      membersIds.push(...participantIds);
    } else if (m.value === 'BUNDLE_ORGANIZATIONS') {
      const bundleOrganizations = bundle.objects.filter((o) => o.extensions[STIX_EXT_OCTI].type === ENTITY_TYPE_IDENTITY_ORGANIZATION);
      const bundleOrganizationsIds = bundleOrganizations.map((o) => o.extensions[STIX_EXT_OCTI].id);
      membersIds.push(...bundleOrganizationsIds);
    } else {
      membersIds.push(m.value);
    }
  });

  const users = platformUsers.filter((user) => {
    if (isInternalUser(user)) return false;
    const isDirectlyAuthorized = membersIds.includes(user.id);
    const isAuthorizedByGroup = user.groups.some((g) => membersIds.includes(g.internal_id));
    const isAuthorizedByOrganization = user.organizations.some((o) => membersIds.includes(o.internal_id));
    return isDirectlyAuthorized || isAuthorizedByGroup || isAuthorizedByOrganization;
  });
  return R.uniqBy(R.prop('id'), users);
};

export const applyOperationFieldPatch = (element: StixObject, patchObject: {
  key: string;
  value: any[];
  operation: 'add' | 'replace' | 'remove';
}[]) => {
  if (!element.extensions[STIX_EXT_OCTI].opencti_upsert_operations) {
    element.extensions[STIX_EXT_OCTI].opencti_upsert_operations = [];
  }
  element.extensions[STIX_EXT_OCTI].opencti_upsert_operations.push(...patchObject);
};

export const deleteLinksAndAllChildren = (definition: ComponentDefinition, links: LinkDefinition[]) => {
  // Resolve all nodes to delete
  const linksToDelete = links;
  const nodesToDelete = [] as NodeDefinition[];
  let childrenLinks = [] as LinkDefinition[];
  // Resolve children nodes
  let childrenNodes = definition.nodes.filter((n) => links.map((o) => o.to.id).includes(n.id));
  if (childrenNodes.length > 0) {
    nodesToDelete.push(...childrenNodes);
    childrenLinks = definition.links.filter((n) => childrenNodes.map((o) => o.id).includes(n.from.id));
  }
  while (childrenLinks.length > 0) {
    linksToDelete.push(...childrenLinks);
    // Resolve children nodes not already in nodesToDelete
    childrenNodes = definition.nodes.filter((n) => linksToDelete.map((o) => o.to.id).includes(n.id) && !nodesToDelete.map((o) => o.id).includes(n.id));
    if (childrenNodes.length > 0) {
      nodesToDelete.push(...childrenNodes);

      childrenLinks = definition.links.filter((n) => childrenNodes.map((o) => o.id).includes(n.from.id));
    } else {
      childrenLinks = [];
    }
    logApp.info('Delete links and children loop', { nodesToDelete, linksToDelete });
  }
  return {
    nodes: definition.nodes.filter((n) => !nodesToDelete.map((o) => o.id).includes(n.id)),
    links: definition.links.filter((n) => !linksToDelete.map((o) => o.id).includes(n.id)),
  };
};

export const checkPlaybookFiltersAndBuildConfigWithCorrectFilters = async (
  context: AuthContext,
  user: AuthUser,
  input: PlaybookAddNodeInput,
  userId: string,
) => {
  if (!input.configuration) {
    return '{}';
  }
  let stringifiedFilters;
  const config = JSON.parse(input.configuration);
  if (config.filters) {
    const filterGroup = JSON.parse(config.filters) as FilterGroup;
    if (input.component_id === PLAYBOOK_INTERNAL_DATA_CRON.id) {
      const convertedFilters = await checkAndConvertFilters(context, user, filterGroup, userId, elFindByIds as FiltersIdsFinder, { noFiltersConvert: true });
      stringifiedFilters = JSON.stringify(convertedFilters);
    } else {
      // our stix matching is currently limited, we need to validate the input filters
      validateFilterGroupForStixMatch(filterGroup);
      stringifiedFilters = config.filters;
    }
  }
  return JSON.stringify({ ...config, filters: stringifiedFilters });
};
