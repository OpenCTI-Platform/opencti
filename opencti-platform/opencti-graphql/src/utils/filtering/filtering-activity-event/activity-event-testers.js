import { testStringFilter } from '../boolean-logic-engine';
//-----------------------------------------------------------------------------------
// Event testers for each possible filter.
/**
 * EVENT TYPE
 */
export const testEventType = (event, filter) => {
    const value = event.type;
    return testStringFilter(filter, [value]);
};
/**
 * EVENT SCOPE
 */
export const testEventScope = (event, filter) => {
    const value = event.event_scope;
    return testStringFilter(filter, [value]);
};
/**
 * MEMBERS USER
 */
export const testMembersUser = (event, filter) => {
    var _a;
    const value = (_a = event.origin.user_id) !== null && _a !== void 0 ? _a : '<unknown>';
    return testStringFilter(filter, [value]);
};
/**
 * MEMBERS GROUP
 */
export const testMembersGroup = (event, filter) => {
    var _a;
    const values = (_a = event.origin.group_ids) !== null && _a !== void 0 ? _a : [];
    return testStringFilter(filter, values);
};
/**
 * MEMBERS ORGANIZATION
 */
export const testMembersOrganization = (event, filter) => {
    var _a;
    const values = (_a = event.origin.organization_ids) !== null && _a !== void 0 ? _a : [];
    return testStringFilter(filter, values);
};
/**
 * MEMBERS USER
 */
export const testActivityStatuses = (event, filter) => {
    const value = event.status;
    return testStringFilter(filter, [value]);
};
export const FILTER_WITH_EVENTS_KEY_TESTERS_MAP = {
    event_type: testEventType,
    event_scope: testEventScope,
    members_user: testMembersUser,
    members_group: testMembersGroup,
    members_organization: testMembersOrganization,
    activity_statuses: testActivityStatuses,
};
