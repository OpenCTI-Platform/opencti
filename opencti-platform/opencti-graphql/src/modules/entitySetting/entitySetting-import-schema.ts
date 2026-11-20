import { z } from 'zod';

const MAX_ENTITY_TYPE_LENGTH = 255;
const MAX_HIDDEN_ENTITY_TYPES = 1000;

// The hidden entity types of a configuration: the entity types hidden for the whole platform, as the export writes them.
// Unknown keys are rejected; which types can be hidden on this platform is decided by the import, not by the shape.
export const hiddenEntityTypesImportSchema = z.strictObject({
  hidden_entity_types: z.array(z.string().min(1).max(MAX_ENTITY_TYPE_LENGTH)).max(MAX_HIDDEN_ENTITY_TYPES),
});

export type HiddenEntityTypesImportConfiguration = z.infer<typeof hiddenEntityTypesImportSchema>;
