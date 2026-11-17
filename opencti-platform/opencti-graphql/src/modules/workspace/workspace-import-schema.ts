import { z } from 'zod';
import { fromB64 } from '../../utils/base64';

// The rules of a dashboard to import from a configuration bundle: strict, unknown keys are rejected.
// A dashboard is found by its name on the platform (its standard id is random).
// A name is a keyword of the index: a longer one could never be found again
export const DASHBOARD_NAME_MAX_LENGTH = 512;

const isRecord = (value: unknown): value is Record<string, unknown> => typeof value === 'object' && value !== null && !Array.isArray(value);

// The manifest is the base64 JSON of the dashboard file. What the platform reads without checking is checked here, so that the item fails
// with a reason instead of an error: the widgets and their data selection, the variables
const isValidManifest = (encoded: string | null | undefined) => {
  if (!encoded) {
    return true;
  }
  try {
    const manifest = fromB64(encoded);
    if (!isRecord(manifest)) {
      return false;
    }
    const { widgets, variables } = manifest;
    const widgetsAreValid = widgets === undefined || (isRecord(widgets) && Object.values(widgets).every((widget) => isRecord(widget) && Array.isArray(widget.dataSelection)));
    return widgetsAreValid && (variables === undefined || Array.isArray(variables));
  } catch {
    return false;
  }
};

export const dashboardImportSchema = z.strictObject({
  name: z.string().trim().min(2, 'Dashboard name must be at least 2 characters').max(DASHBOARD_NAME_MAX_LENGTH, `Dashboard name must be at most ${DASHBOARD_NAME_MAX_LENGTH} characters`),
  // Absent or null: a new dashboard is given none, and an existing one is left untouched. The same for every field below
  description: z.string().nullable().optional(),
  tags: z.array(z.string()).nullable().optional(),
  refresh_interval: z.number().int().min(0).nullable().optional(),
  manifest: z.string().nullable().optional().refine(isValidManifest, 'Invalid dashboard manifest'),
  // Who can open the dashboard is not part of a bundle, as in the file import: the importing user is its admin
});

export type DashboardImportConfiguration = z.infer<typeof dashboardImportSchema>;
