import { z } from 'zod';

// The rules of a fintel template to import from a configuration bundle: strict, unknown keys are rejected.
// A template is found by its standard id. It is random, so a template is found again on the platform it comes from, never on another one:
// the built-in templates of two platforms are two templates.

// A name is a keyword of the index: a longer one could never be found again
export const FINTEL_TEMPLATE_NAME_MAX_LENGTH = 512;

export const FINTEL_TEMPLATE_STANDARD_ID_PATTERN = /^finteltemplate--[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;

// A widget as the export writes it: what the platform reads without checking is checked here (its data selection), so that the item fails with
// a reason instead of an error. The rest of the widget is the one of a dashboard widget, kept as it is
const fintelTemplateWidgetSchema = z.object({
  variable_name: z.string().min(1, 'The variable name of a widget is required'),
  widget: z.looseObject({
    type: z.string(),
    dataSelection: z.array(z.looseObject({})),
  }),
});

const nullableDate = z.string().refine((value) => !Number.isNaN(Date.parse(value)), 'Must be a date').nullable();

export const fintelTemplateImportSchema = z.strictObject({
  // The identity of the template: required, a template is found by it
  standard_id: z.string().regex(FINTEL_TEMPLATE_STANDARD_ID_PATTERN, 'Must be a fintel template standard id'),
  // Trimmed as the platform stores it, with the rules of the API: at least two characters
  name: z.string()
    .trim()
    .refine((name) => name.length >= 2, 'Fintel template name must be at least 2 characters')
    .refine((name) => name.length <= FINTEL_TEMPLATE_NAME_MAX_LENGTH, `Fintel template name must be at most ${FINTEL_TEMPLATE_NAME_MAX_LENGTH} characters`),
  // The entity type the template applies to: one, as the platform reads only the first
  settings_types: z.array(z.string().trim().min(1)).length(1, 'A fintel template applies to one entity type'),
  // A key the bundle does not have leaves the value of an existing template untouched. A key it has is written, null or empty included:
  // no description, no instance filter, or a template that is not published (no start date)
  description: z.string().nullable().optional(),
  instance_filters: z.string().nullable().optional(),
  template_content: z.string().optional(),
  start_date: nullableDate.optional(),
  fintel_template_widgets: z.array(fintelTemplateWidgetSchema).optional(),
  // The default template of its entity type on the platform it was exported from: it becomes the default of that type
  default: z.boolean().optional(),
  include_cover_page_by_default: z.boolean().optional(),
  include_back_page_by_default: z.boolean().optional(),
});

export type FintelTemplateImportConfiguration = z.infer<typeof fintelTemplateImportSchema>;
