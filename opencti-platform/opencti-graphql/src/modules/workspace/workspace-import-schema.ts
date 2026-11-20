import { z } from 'zod';
import { readManifestWithValidWidgets } from '../dashboard/dashboard-utils';

// The rules of a dashboard to import from a configuration bundle: strict, unknown keys are rejected.
// A dashboard is found by its name on the platform (its standard id is random).
// A name is a keyword of the index: a longer one could never be found again
export const DASHBOARD_NAME_MAX_LENGTH = 512;

// The manifest is the base64 JSON of the dashboard file. What the platform reads without checking is checked here, so that the item fails
// with a reason instead of an error: the widgets and their data selection, the variables
const isValidManifest = (encoded: string | null | undefined) => {
  if (!encoded) {
    return true;
  }
  const manifest = readManifestWithValidWidgets(encoded);
  return manifest !== undefined && (manifest.variables === undefined || Array.isArray(manifest.variables));
};

export const dashboardImportSchema = z.strictObject({
  // The name as the platform stores it: the platform trims every string at indexing, so a dashboard is never stored with spaces around its name.
  // Trimmed here too, so that the dashboard an export wrote is found again by its name (else an overwrite would create a second one).
  // Not blank (what the file import accepts), no minimum length (what the edition of a dashboard allows)
  name: z.string()
    .trim()
    .refine((name) => name.length > 0, 'Dashboard name is required')
    .refine((name) => name.length <= DASHBOARD_NAME_MAX_LENGTH, `Dashboard name must be at most ${DASHBOARD_NAME_MAX_LENGTH} characters`),
  // Absent or null: a new dashboard is given none, and an existing one is left untouched. The same for every field below
  description: z.string().nullable().optional(),
  tags: z.array(z.string()).nullable().optional(),
  refresh_interval: z.number().int().min(0).nullable().optional(),
  manifest: z.string().nullable().optional().refine(isValidManifest, 'Invalid dashboard manifest'),
  // Who can open the dashboard is not part of a bundle, as in the file import: the importing user is its admin
});

export type DashboardImportConfiguration = z.infer<typeof dashboardImportSchema>;
