import type { TesterFunction } from '../boolean-logic-engine';
import { testStringFilter } from '../boolean-logic-engine';
import type { Filter } from '../../../generated/graphql';

//-----------------------------------------------------------------------------------
// Event testers for each possible filter.

/**
 * EVENT TYPE
 */
export const testEventType = (event: any, filter: Filter) => {
  const value = event.type;
  return testStringFilter(filter, [value]);
};

/**
 * EVENT SCOPE
 */
export const testEventScope = (event: any, filter: Filter) => {
  const value = event.event_scope;
  return testStringFilter(filter, [value]);
};

/**
 * MEMBERS USER
 */
export const testMembersUser = (event: any, filter: Filter) => {
  const value = event.origin.user_id ?? '<unknown>';
  return testStringFilter(filter, [value]);
};

/**
 * MEMBERS GROUP
 */
export const testMembersGroup = (event: any, filter: Filter) => {
  const values = event.origin.group_ids ?? [];
  return testStringFilter(filter, values);
};

/**
 * MEMBERS ORGANIZATION
 */
export const testMembersOrganization = (event: any, filter: Filter) => {
  const values = event.origin.organization_ids ?? [];
  return testStringFilter(filter, values);
};

/**
 * MEMBERS USER
 */
export const testActivityStatuses = (event: any, filter: Filter) => {
  const value = event.status;
  return testStringFilter(filter, [value]);
};

export const FILTER_WITH_EVENTS_KEY_TESTERS_MAP: Record<string, TesterFunction> = {
  event_type: testEventType,
  event_scope: testEventScope,
  members_user: testMembersUser,
  members_group: testMembersGroup,
  members_organization: testMembersOrganization,
  activity_statuses: testActivityStatuses,
};
