var __awaiter = (this && this.__awaiter) || function (thisArg, _arguments, P, generator) {
    function adopt(value) { return value instanceof P ? value : new P(function (resolve) { resolve(value); }); }
    return new (P || (P = Promise))(function (resolve, reject) {
        function fulfilled(value) { try { step(generator.next(value)); } catch (e) { reject(e); } }
        function rejected(value) { try { step(generator["throw"](value)); } catch (e) { reject(e); } }
        function step(result) { result.done ? resolve(result.value) : adopt(result.value).then(fulfilled, rejected); }
        step((generator = generator.apply(thisArg, _arguments || [])).next());
    });
};
import { FILTER_WITH_EVENTS_KEY_TESTERS_MAP } from './activity-event-testers';
import { testFilterGroup } from '../boolean-logic-engine';
import { UnsupportedError } from '../../../config/errors';
//----------------------------------------------------------------------------------------------------------------------
// Validate Filter in case of comparison against an event
export const validateFilterForActivityEventMatch = (filter) => {
    if (!Array.isArray(filter.key)) {
        throw UnsupportedError('The provided filter key is not an array', { key: JSON.stringify(filter.key) });
    }
    if (filter.key.length !== 1) {
        throw UnsupportedError('Activity Stream Event filtering can only be executed on a unique filter key', { key: JSON.stringify(filter.key) });
    }
    if (FILTER_WITH_EVENTS_KEY_TESTERS_MAP[filter.key[0]] === undefined) {
        const availableFilters = JSON.stringify(Object.keys(FILTER_WITH_EVENTS_KEY_TESTERS_MAP));
        throw UnsupportedError('Activity Stream Event filtering is not compatible with the provided filter key', { key: JSON.stringify(filter.key), availableFilters });
    }
};
export const validateFilterGroupForActivityEventMatch = (filterGroup) => {
    if (!(filterGroup === null || filterGroup === void 0 ? void 0 : filterGroup.filterGroups) || !(filterGroup === null || filterGroup === void 0 ? void 0 : filterGroup.filters)) {
        throw UnsupportedError('Unrecognized filter format; expecting FilterGroup');
    }
    filterGroup.filters.forEach((f) => validateFilterForActivityEventMatch(f));
    filterGroup.filterGroups.forEach((fg) => validateFilterGroupForActivityEventMatch(fg));
};
//----------------------------------------------------------------------------------------------------------------------
/**
 * Tells if a given Activity Stream Event matches the given filter
 * @param event
 * @param filterGroup
 */
export const isActivityEventMatchFilterGroup = (event, filterGroup) => __awaiter(void 0, void 0, void 0, function* () {
    // check the filter is well formed and compatible for event matching
    if (filterGroup)
        validateFilterGroupForActivityEventMatch(filterGroup);
    if (!filterGroup)
        return true; // if no filters: the event always match
    // then call our boolean engine on the filter group using the event testers
    return testFilterGroup(event, filterGroup, FILTER_WITH_EVENTS_KEY_TESTERS_MAP);
});
