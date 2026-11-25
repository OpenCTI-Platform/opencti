import { z } from 'zod';
import { readManifestWithValidWidgets } from '../dashboard/dashboard-utils';

// The rules of a custom view to import from a configuration bundle: strict, unknown keys are rejected.
// A custom view is found by its entity type and its name on the platform (its standard id is random).
// A name is a keyword of the index: a longer one could never be found again
export const CUSTOM_VIEW_NAME_MAX_LENGTH = 512;

// The manifest is the base64 JSON of the custom view. What the platform reads without checking is checked here, so that the item fails
// with a reason instead of an error: the widgets and their data selection.
// The variables and the presets are not read: a custom view never keeps them (the manifest is stripped of them at every write)
const isValidManifest = (encoded: string | null | undefined) => {
  if (!encoded) {
    return true;
  }
  return readManifestWithValidWidgets(encoded) !== undefined;
};

export const customViewImportSchema = z.strictObject({
  // The name as the platform stores it: the platform trims every string at indexing, so a custom view is never stored with spaces around its name.
  // Trimmed here too, so that the view an export wrote is found again by its name (else an overwrite would create a second one)
  name: z.string()
    .trim()
    .refine((name) => name.length > 0, 'Custom view name is required')
    .refine((name) => name.length <= CUSTOM_VIEW_NAME_MAX_LENGTH, `Custom view name must be at most ${CUSTOM_VIEW_NAME_MAX_LENGTH} characters`),
  // The entity type the view applies to: part of its identity, and always in a bundle (the file import lets the user choose it)
  target_entity_type: z.string()
    .trim()
    .refine((type) => type.length > 0, 'Target entity type is required'),
  // Absent or null: a new custom view is given none, and an existing one is left untouched. The same for the manifest.
  // Trimmed as the platform stores it, else a padded description would differ from the stored one and be patched at every overwrite
  description: z.string().trim().nullable().optional(),
  manifest: z.string().nullable().optional().refine(isValidManifest, 'Invalid custom view manifest'),
  // Whether the view is enabled or the default of its entity type is not part of a bundle: an imported view is neither
});

export type CustomViewImportConfiguration = z.infer<typeof customViewImportSchema>;
