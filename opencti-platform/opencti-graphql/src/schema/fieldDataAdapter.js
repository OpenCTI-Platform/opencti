import * as R from 'ramda';
import { isDatedInternalObject } from './internalObject';
import { isStixCoreObject } from './stixCoreObject';
import { isStixCoreRelationship } from './stixCoreRelationship';
import { isStixSightingRelationship } from './stixSightingRelationship';
import { isStixMetaObject } from './stixMetaObject';
import { isStixDomainObject } from './stixDomainObject';
export const SENSITIVE_HASHES = ['SSDEEP', 'SDHASH'];
export const FUZZY_HASH_ALGORITHMS = ['SSDEEP', 'SDHASH', 'TLSH', 'LZJD'];
export const noReferenceAttributes = ['x_opencti_graph_data'];
export const dateForStartAttributes = ['first_seen', 'start_time', 'valid_from', 'first_observed'];
export const dateForEndAttributes = ['last_seen', 'stop_time', 'valid_until', 'last_observed'];
export const dateForLimitsAttributes = [...dateForStartAttributes, ...dateForEndAttributes];
// Extract all not fuzzy algorithm values from a hash object
export const extractNotFuzzyHashValues = (hashes) => {
    return Object.entries(hashes)
        .filter(([hashKey]) => !FUZZY_HASH_ALGORITHMS.includes(hashKey.toUpperCase()))
        .map(([, hashValue]) => hashValue)
        .filter((hashValue) => hashValue);
};
// Must be call as soon as possible in the according resolvers
export const inputHashesToStix = (data) => {
    const inputs = Array.isArray(data) ? data : [data];
    const convertedInputs = inputs.map((d) => {
        const hashAlgorithm = d.algorithm.toUpperCase().trim();
        const hashValue = SENSITIVE_HASHES.includes(hashAlgorithm) ? d.hash : d.hash.toLowerCase();
        return [hashAlgorithm, hashValue.trim()];
    });
    return R.fromPairs(convertedInputs);
};
// Must only be call in generic resolvers for data output
export const stixHashesToInput = (instance) => {
    var _a;
    const attributeValue = (_a = instance.hashes) !== null && _a !== void 0 ? _a : {};
    const entries = Object.entries(attributeValue);
    return entries.map(([lab, val]) => {
        return { algorithm: lab.toUpperCase().trim(), hash: val.trim() };
    });
};
export const isUpdatedAtObject = (type) => {
    return (isDatedInternalObject(type)
        || isStixMetaObject(type)
        || isStixCoreObject(type)
        || isStixCoreRelationship(type)
        || isStixSightingRelationship(type));
};
export const isModifiedObject = (type) => {
    return (isStixMetaObject(type)
        || isStixDomainObject(type)
        || isStixCoreRelationship(type)
        || isStixSightingRelationship(type));
};
