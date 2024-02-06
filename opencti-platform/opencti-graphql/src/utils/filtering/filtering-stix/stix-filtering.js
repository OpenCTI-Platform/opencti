var __awaiter = (this && this.__awaiter) || function (thisArg, _arguments, P, generator) {
    function adopt(value) { return value instanceof P ? value : new P(function (resolve) { resolve(value); }); }
    return new (P || (P = Promise))(function (resolve, reject) {
        function fulfilled(value) { try { step(generator.next(value)); } catch (e) { reject(e); } }
        function rejected(value) { try { step(generator["throw"](value)); } catch (e) { reject(e); } }
        function step(result) { result.done ? resolve(result.value) : adopt(result.value).then(fulfilled, rejected); }
        step((generator = generator.apply(thisArg, _arguments || [])).next());
    });
};
import { FILTER_KEY_TESTERS_MAP } from './stix-testers';
import { testFilterGroup } from '../boolean-logic-engine';
import { isUserCanAccessStixElement, SYSTEM_USER } from '../../access';
import { getEntitiesMapFromCache } from '../../../database/cache';
import { ENTITY_TYPE_RESOLVED_FILTERS } from '../../../schema/stixDomainObject';
import { buildResolutionMapForFilterGroup, resolveFilterGroup } from '../filtering-resolution';
import { UnsupportedError } from '../../../config/errors';
//----------------------------------------------------------------------------------------------------------------------
/**
 * Pass through all individual filters and throws an error if it cannot be handled properly.
 * This is very aggressive but will allow us to detect rapidly any corner-case.
 */
export const validateFilterForStixMatch = (filter) => {
    if (!Array.isArray(filter.key)) {
        throw UnsupportedError('The provided filter key is not an array', { key: JSON.stringify(filter.key) });
    }
    if (filter.key.length !== 1) {
        throw UnsupportedError('Stix filtering can only be executed on a unique filter key', { key: JSON.stringify(filter.key) });
    }
    if (FILTER_KEY_TESTERS_MAP[filter.key[0]] === undefined) {
        const availableFilters = JSON.stringify(Object.keys(FILTER_KEY_TESTERS_MAP));
        throw UnsupportedError('Stix filtering is not compatible with the provided filter key', { key: JSON.stringify(filter.key), availableFilters });
    }
};
/**
 * Recursively call validateFilter inside a FilterGroup
 */
export const validateFilterGroupForStixMatch = (filterGroup) => {
    if (!(filterGroup === null || filterGroup === void 0 ? void 0 : filterGroup.filterGroups) || !(filterGroup === null || filterGroup === void 0 ? void 0 : filterGroup.filters)) {
        throw UnsupportedError('Unrecognized filter format; expecting FilterGroup');
    }
    filterGroup.filters.forEach((f) => validateFilterForStixMatch(f));
    filterGroup.filterGroups.forEach((fg) => validateFilterGroupForStixMatch(fg));
};
//----------------------------------------------------------------------------------------------------------------------
// STIX MATCH
/**
 * Middleware function that allow us to make unit tests by mocking the resolution map.
 * This is necessary because the map is built thanks to the cache, not available in unit tests.
 */
export const isStixMatchFilterGroup_MockableForUnitTests = (context, user, stix, filterGroup, resolutionMap) => __awaiter(void 0, void 0, void 0, function* () {
    // we are limited to certain filter keys right now, so better throw an explicit error if a key is not compatible
    // Note that similar check is done when saving a filter in stream, taxii, feed, or playbook node.
    // This check should thus not fail here, theoretically.
    if (filterGroup)
        validateFilterGroupForStixMatch(filterGroup);
    // first check: user access right (according to markings, organization, etc.)
    const isUserHasAccessToElement = yield isUserCanAccessStixElement(context, user, stix);
    if (!isUserHasAccessToElement) {
        return false;
    }
    // if no filters and the user has access: the stix always match
    if (!filterGroup)
        return true;
    // replace the ids in values if necessary, to adapt to the stix format
    const resolvedFilterGroup = yield resolveFilterGroup(context, user, filterGroup, resolutionMap);
    // then call our boolean engine on the filter group using the stix testers
    return testFilterGroup(stix, resolvedFilterGroup, FILTER_KEY_TESTERS_MAP);
});
/**
 * Tells if a stix object matches a filter group given a certain context.
 * The input filter group is a stored filter (streams, triggers, playbooks), the stix object comes from the raw stream.
 *
 * This function will first check the user access rights to the stix object, then resolve parts of the filter groups if necessary,
 * prior to actually comparing the filter values with the stix values.
 * @param context
 * @param user
 * @param stix stix object from the raw event stream
 * @param filterGroup
 * @throws {Error} on invalid filter keys
 */
export const isStixMatchFilterGroup = (context, user, stix, filterGroup) => __awaiter(void 0, void 0, void 0, function* () {
    // resolve some of the ids as we filter on their corresponding values or standard-id for instance
    // the provided map will contain replacements for filter values, if any necessary.
    // we use the entities stored in cache for the "Resolved-Filters" (all the entities used by the saved filters - stream, trigger, playbooks)
    // see cacheManager.ts:platformResolvedFilters
    const cache = yield getEntitiesMapFromCache(context, SYSTEM_USER, ENTITY_TYPE_RESOLVED_FILTERS);
    const map = filterGroup ? yield buildResolutionMapForFilterGroup(context, user, filterGroup, cache) : new Map();
    return isStixMatchFilterGroup_MockableForUnitTests(context, user, stix, filterGroup, map);
});
