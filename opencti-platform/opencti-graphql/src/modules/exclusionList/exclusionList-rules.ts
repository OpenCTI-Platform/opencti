import { z } from 'zod';

// The shortest name of an exclusion list. The one rule of every way to create a list: the creation form of the UI, the API and the import of
// a configuration preset all go through the domain, which checks the name with this schema. The creation form of the front (ExclusionListUtils.ts)
// states the same length to tell the user before the request: the front cannot import it from here, so keep them equal.
export const EXCLUSION_LIST_NAME_MIN_LENGTH = 2;

export const exclusionListNameSchema = z.string().trim().min(EXCLUSION_LIST_NAME_MIN_LENGTH, `Exclusion list name must have at least ${EXCLUSION_LIST_NAME_MIN_LENGTH} characters`);

// The types a list has, whatever their order
export const hasSameTypes = (existing: string[], types: string[]) => {
  return existing.length === types.length && [...existing].sort().join() === [...types].sort().join();
};
