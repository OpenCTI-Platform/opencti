/**
 * PoC #2 (merge users investigation) - "alias" prototype.
 *
 * This module is a throwaway prototype used to measure the impact of redirecting
 * reads of a "source" user id to a "target" user id, WITHOUT rewriting any stored data.
 *
 * It is opt-in only: with the env var unset, `getMergeUsersPocAliasMap()` returns an
 * empty map and `resolveMergeUsersPocAliasId()` is a no-op, so default production
 * behavior is strictly unchanged.
 *
 * Enable with:
 *   MERGE_POC_ALIAS_MAP='{"<sourceUserId>":"<targetUserId>"}'
 *
 * See PR description ("Résultats du PoC") for what this does and does not cover.
 */

let cachedRawValue: string | undefined;
let cachedAliasMap: Map<string, string> = new Map();

const parseAliasMap = (raw: string | undefined): Map<string, string> => {
  if (!raw) {
    return new Map();
  }
  try {
    const parsed = JSON.parse(raw);
    return new Map(Object.entries(parsed));
  } catch {
    // Fail closed: an invalid value must not accidentally enable the redirection.
    return new Map();
  }
};

// Lazily parsed (and re-parsed if the env var changes, e.g. between test cases).
const getMergeUsersPocAliasMap = (): Map<string, string> => {
  const raw = process.env.MERGE_POC_ALIAS_MAP;
  if (raw !== cachedRawValue) {
    cachedRawValue = raw;
    cachedAliasMap = parseAliasMap(raw);
  }
  return cachedAliasMap;
};

/**
 * Returns the "target" id to use instead of the given id if it is registered
 * as a PoC alias "source", otherwise returns the id unchanged.
 */
export const resolveMergeUsersPocAliasId = (id: string): string => {
  const aliasMap = getMergeUsersPocAliasMap();
  return aliasMap.get(id) ?? id;
};

export const isMergeUsersPocAliasEnabled = (): boolean => getMergeUsersPocAliasMap().size > 0;
