import type { KeyValuePair } from 'ramda';
import * as R from 'ramda';
import { isDatedInternalObject } from './internalObject';
import { isStixCoreObject } from './stixCoreObject';
import { isStixCoreRelationship } from './stixCoreRelationship';
import { isStixSightingRelationship } from './stixSightingRelationship';
import { isStixMetaObject } from './stixMetaObject';
import { isStixDomainObject } from './stixDomainObject';
import type { StixArtifact, StixFile, StixX509Certificate } from '../types/stix-sco';
import type { HashInput } from '../generated/graphql';
import { MD5, SHA_1, SHA_256, SHA_512, SHA3_256, SHA3_512, LZJD, SDHASH, SSDEEP, TLSH } from './identifier';
import { UnsupportedError } from '../config/errors';

export const SENSITIVE_HASHES = [SSDEEP, SDHASH];
export const KEY_HASH_ALGORITHMS = [MD5, SHA_1, SHA_256, SHA_512, SHA3_256, SHA3_512];
export const FUZZY_HASH_ALGORITHMS = [...SENSITIVE_HASHES, TLSH, LZJD];
export const SUPPORTED_HASH_ALGORITHMS = [...KEY_HASH_ALGORITHMS, ...FUZZY_HASH_ALGORITHMS];

export const noReferenceAttributes = ['x_opencti_graph_data'];
export const dateForStartAttributes = ['first_seen', 'start_time', 'valid_from', 'first_observed'];
export const dateForEndAttributes = ['last_seen', 'stop_time', 'valid_until', 'last_observed'];
export const dateForLimitsAttributes = [...dateForStartAttributes, ...dateForEndAttributes];

// Extract all not fuzzy algorithm values from a hash object
export const extractKeyHashKeys = (hashes: Record<string, string>): Array<string> => {
  return Object.keys(hashes).filter((hashKey) => KEY_HASH_ALGORITHMS.includes(hashKey.toUpperCase())).map((s) => `hashes.${s}`);
};
export const extractKeyHashValues = (hashes: Record<string, string>): Array<string> => {
  return Object.entries(hashes)
    .filter(([hashKey]) => KEY_HASH_ALGORITHMS.includes(hashKey.toUpperCase()))
    .map(([, hashValue]) => hashValue)
    .filter((hashValue) => hashValue);
};

// Must be call as soon as possible in the according resolvers
export const inputHashesToStix = (data: Array<HashInput>) => {
  const inputs = Array.isArray(data) ? data : [data];
  const convertedInputs = inputs.map((d) => {
    const hashAlgorithm = d.algorithm.toUpperCase().trim();
    if (!SUPPORTED_HASH_ALGORITHMS.includes(hashAlgorithm)) {
      throw UnsupportedError(`Hash ${hashAlgorithm} algorithm not supported`, { supported: SUPPORTED_HASH_ALGORITHMS });
    }
    const hashValue = SENSITIVE_HASHES.includes(hashAlgorithm) ? d.hash : d.hash.toLowerCase();
    return [hashAlgorithm, hashValue.trim()] as KeyValuePair<string, string>;
  });
  return R.fromPairs(convertedInputs);
};

// Must only be call in generic resolvers for data output
export const stixHashesToInput = (instance: StixArtifact | StixFile | StixX509Certificate): Array<HashInput> => {
  const attributeValue = instance.hashes ?? {};
  const entries = Object.entries(attributeValue);
  return entries.map(([lab, val]) => {
    return { algorithm: lab.toUpperCase().trim(), hash: val.trim() };
  });
};

export const isUpdatedAtObject = (type: string): boolean => {
  return (
    isDatedInternalObject(type)
    || isStixMetaObject(type)
    || isStixCoreObject(type)
    || isStixCoreRelationship(type)
    || isStixSightingRelationship(type)
  );
};

export const isModifiedObject = (type: string): boolean => {
  return (
    isStixMetaObject(type)
    || isStixDomainObject(type)
    || isStixCoreRelationship(type)
    || isStixSightingRelationship(type)
  );
};
