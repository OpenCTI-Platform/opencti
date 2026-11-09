import { z } from 'zod';
import { exclusionListNameSchema } from './exclusionList-rules';

// The types an exclusion list can hold, the ones of the creation form. The values of the list are not here: they are the file next to it.
const IP_ENTITY_TYPES = ['IPv4-Addr', 'IPv6-Addr'] as const;
const OBSERVABLE_ENTITY_TYPES = ['Artifact', 'Domain-Name', 'Hostname', 'Url', 'StixFile', 'Email-Addr'] as const;
const EXCLUSION_LIST_ENTITY_TYPES = [...OBSERVABLE_ENTITY_TYPES, ...IP_ENTITY_TYPES] as const;

const isIpType = (type: string) => (IP_ENTITY_TYPES as readonly string[]).includes(type);

// The rules of an exclusion list to import, whatever the source (a configuration preset): strict, unknown keys are rejected.
export const exclusionListImportSchema = z.strictObject({
  // The standard id of an exclusion list is random: a list is found by its name, which has the length the creation of a list requires
  name: exclusionListNameSchema,
  // Absent or null: the description of an existing list is left untouched
  description: z.string().nullable().optional(),
  // Absent: a new list is enabled, and an existing one keeps its state
  enabled: z.boolean().optional(),
  // The form refuses a list that mixes IP types with other types: a list is checked either as addresses or as values
  exclusion_list_entity_types: z.array(z.enum(EXCLUSION_LIST_ENTITY_TYPES)).min(1, 'At least one entity type is required').refine(
    (types) => types.every(isIpType) || !types.some(isIpType),
    'IP types cannot be mixed with other types',
  ).refine(
    // A type given twice is not the types of the list that has it once: an import would write it again every time
    (types) => new Set(types).size === types.length,
    'An entity type is given twice',
  ),
});

export type ExclusionListImportConfiguration = z.infer<typeof exclusionListImportSchema>;
