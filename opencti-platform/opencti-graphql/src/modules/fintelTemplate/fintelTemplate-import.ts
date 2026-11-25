import * as R from 'ramda';
import { GraphQLError } from 'graphql';
import { FUNCTIONAL_ERROR, FunctionalError } from '../../config/errors';
import { type EditInput, FilterMode, type FintelTemplateWidgetAddInput } from '../../generated/graphql';
import { fullEntitiesList, storeLoadById } from '../../database/middleware-loader';
import type { AuthContext, AuthUser } from '../../types/user';
import { ConfigImportMode, type ConfigImportOptions, type ConfigImportResult } from '../configImport/configImport-types';
import {
  CONFIG_IMPORT_UNCHANGED_REASON,
  configImportReasonValue,
  configImportRefusal,
  configImportValidationReason,
  freeConfigImportName,
} from '../configImport/configImport-utils';
import {
  addFintelTemplate,
  checkFintelTemplateWidgetsValidity,
  fintelTemplateEditField,
  type FintelTemplateWidgetFromImport,
  toImportedFintelTemplateWidgets,
} from './fintelTemplate-domain';
import { FINTEL_TEMPLATE_NAME_MAX_LENGTH, type FintelTemplateImportConfiguration, fintelTemplateImportSchema } from './fintelTemplate-import-schema';
import { type BasicStoreEntityFintelTemplate, ENTITY_TYPE_FINTEL_TEMPLATE } from './fintelTemplate-types';

export type FintelTemplateImportCode = 'invalid' | 'exists' | 'entity_type' | 'name_conflict' | 'unchanged';

export interface FintelTemplateImportOptions extends ConfigImportOptions {
  // A dry run writes nothing: the names the earlier items of the same dry run would give (a copy, a creation, a rename) are reserved for the
  // next ones, by `fintelTemplateImportKey` (the names of two entity types are apart)
  reservedNames?: Set<string>;
  // The ids of the templates an earlier item of the same dry run renames: the name they have now is no longer theirs.
  // Ids and not names: two templates can have the same name, and the other one keeps it
  renamedIds?: Set<string>;
}

export type FintelTemplateImportResult = ConfigImportResult<FintelTemplateImportConfiguration, FintelTemplateImportCode> & {
  // The name of a copy: the one of the configuration, or the free one it takes when the template exists
  copyName?: string;
};

const refused = configImportRefusal<FintelTemplateImportConfiguration, FintelTemplateImportCode>;

// The names of the templates of an entity type are apart from the ones of another type: each type has its own templates
export const fintelTemplateImportKey = (settingsType: string, name: string) => `${settingsType}/${name}`;

const isNameTaken = async (context: AuthContext, user: AuthUser, settingsType: string, name: string, { reservedNames, renamedIds }: FintelTemplateImportOptions) => {
  if (reservedNames?.has(fintelTemplateImportKey(settingsType, name))) {
    return true;
  }
  const templates = await fullEntitiesList<BasicStoreEntityFintelTemplate>(context, user, [ENTITY_TYPE_FINTEL_TEMPLATE], {
    filters: {
      mode: FilterMode.And,
      filters: [{ key: ['settings_types'], values: [settingsType] }, { key: ['name'], values: [name] }],
      filterGroups: [],
    },
  });
  // The filter on the name does not tell the case apart
  return templates.some((template) => template.name === name && !renamedIds?.has(template.id));
};

// The widgets with the ids of this platform. A reference it does not have is kept as it is, as the file import does.
// What the widgets break is a refusal of the item (a variable name with spaces, filters the conversion cannot walk), never an error
const prepareWidgets = async (context: AuthContext, user: AuthUser, widgets: FintelTemplateImportConfiguration['fintel_template_widgets']) => {
  if (!widgets) {
    return undefined;
  }
  try {
    checkFintelTemplateWidgetsValidity(widgets as unknown as FintelTemplateWidgetAddInput[]);
    // The conversion writes in the widgets: a copy, so that the configuration of the result stays the one of the bundle
    return await toImportedFintelTemplateWidgets(context, user, R.clone(widgets) as unknown as FintelTemplateWidgetFromImport[]);
  } catch (error) {
    if (error instanceof TypeError) {
      throw FunctionalError('The filters of the widgets are malformed');
    }
    throw error;
  }
};

// Two lists of widgets are the same when they hold the same widgets in the same order, whatever their ids (given at every write) and the order of
// the keys of their stored filters (the platform stores them as JSON text)
const toComparableWidgets = (widgets: { variable_name: string; widget: object }[]) => widgets.map(({ variable_name, widget }) => {
  const { id: _, dataSelection, ...rest } = widget as { id?: string; dataSelection?: Record<string, unknown>[] };
  const parse = (value: unknown) => (typeof value === 'string' ? JSON.parse(value) : value);
  return {
    variable_name,
    widget: {
      ...rest,
      dataSelection: (dataSelection ?? []).map((selection) => ({
        ...selection,
        filters: parse(selection.filters),
        dynamicFrom: parse(selection.dynamicFrom),
        dynamicTo: parse(selection.dynamicTo),
      })),
    },
  };
});

// The fields an overwrite writes: the ones the bundle has and that differ from the template. A key the bundle does not have is left untouched,
// a key it has is written, null included (no description, no instance filter, a template that is not published).
// The default is only ever set: the previous default of the entity type loses it because another one is set, never otherwise
const buildPatch = (existing: BasicStoreEntityFintelTemplate, data: FintelTemplateImportConfiguration, widgets: FintelTemplateWidgetAddInput[] | undefined) => {
  const patch: EditInput[] = [];
  if (data.name !== existing.name) {
    patch.push({ key: 'name', value: [data.name] });
  }
  const nullableFields = ['description', 'instance_filters', 'template_content'] as const;
  nullableFields.forEach((field) => {
    const value = data[field];
    if (value !== undefined && (value ?? '') !== (existing[field] ?? '')) {
      patch.push({ key: field, value: [value] });
    }
  });
  if (data.start_date !== undefined) {
    const time = (date: string | null | undefined) => (date ? new Date(date).getTime() : null);
    if (time(data.start_date) !== time(existing.start_date)) {
      patch.push({ key: 'start_date', value: [data.start_date] });
    }
  }
  const booleanFields = ['include_cover_page_by_default', 'include_back_page_by_default'] as const;
  booleanFields.forEach((field) => {
    const value = data[field];
    if (value !== undefined && value !== (existing[field] ?? true)) {
      patch.push({ key: field, value: [value] });
    }
  });
  if (widgets && !R.equals(toComparableWidgets(widgets), toComparableWidgets(existing.fintel_template_widgets ?? []))) {
    patch.push({ key: 'fintel_template_widgets', value: widgets });
  }
  if (data.default === true && existing.default !== true) {
    patch.push({ key: 'default', value: [true] });
  }
  return patch;
};

const createFintelTemplate = (
  context: AuthContext,
  user: AuthUser,
  data: FintelTemplateImportConfiguration,
  widgets: FintelTemplateWidgetAddInput[] | undefined,
  { name, isDefault, standardId }: { name: string; isDefault: boolean; standardId?: string },
) => {
  // The widgets are the ones of the bundle only: the built-in widgets a new template gets are already in an exported one
  return addFintelTemplate(context, user, {
    name,
    settings_types: data.settings_types,
    description: data.description ?? undefined,
    instance_filters: data.instance_filters ?? undefined,
    template_content: data.template_content,
    start_date: data.start_date ?? undefined,
    fintel_template_widgets: widgets ?? [],
    default: isDefault,
    include_cover_page_by_default: data.include_cover_page_by_default,
    include_back_page_by_default: data.include_back_page_by_default,
    ...(standardId ? { standard_id: standardId } : {}),
  }, true);
};

// The one place where a fintel template is imported from a configuration bundle: validates, finds the template by its standard id and writes it.
// A refusal is a result, not an error. A dry run decides the same result and writes nothing.
// add: the template must not exist yet. overwrite: the template with the same standard id is patched, else it is created, whatever the names
// of the other templates (two templates can have the same name). copy: the template is created, under a free name of its entity type and a new
// standard id when its own exists.
// The default template of its entity type in the bundle becomes the default of that type, unless it is added as a copy of a template that exists,
// which is another template: as in the UI, the domain then takes the default away from the previous one, so the type keeps exactly one.
// The ids of the filters of the widgets are converted to this platform's: a reference it does not have is kept as it is, as the file import does.
export const importFintelTemplate = async (
  context: AuthContext,
  user: AuthUser,
  configuration: unknown,
  options: FintelTemplateImportOptions,
): Promise<FintelTemplateImportResult> => {
  const { mode, dryRun = false, reservedNames, renamedIds } = options;
  const parsed = fintelTemplateImportSchema.safeParse(configuration);
  if (!parsed.success) {
    return refused('failed', 'invalid', configImportValidationReason(parsed.error), false);
  }
  const { data } = parsed;
  const existing = await storeLoadById<BasicStoreEntityFintelTemplate>(context, user, data.standard_id, ENTITY_TYPE_FINTEL_TEMPLATE);
  if (existing && mode === ConfigImportMode.Add) {
    return refused('failed', 'exists', 'Fintel template already exists', true, data);
  }
  let widgets: FintelTemplateWidgetAddInput[] | undefined;
  try {
    widgets = await prepareWidgets(context, user, data.fintel_template_widgets);
  } catch (error) {
    // Only what the widgets break is a refusal of the item: a failure of the platform (a lookup of the ids that times out) stays an error
    if (!(error instanceof GraphQLError && error.extensions.code === FUNCTIONAL_ERROR)) {
      throw error;
    }
    return refused('failed', 'invalid', configImportReasonValue(error.message), !!existing, data);
  }
  const [settingsType] = data.settings_types;
  // A copy of a template that exists is another template: a new standard id, a free name to tell them apart, and never the default of its
  // entity type, which keeps its own as for the themes. A template that does not exist yet is the template of the bundle
  if (mode === ConfigImportMode.Copy) {
    const name = existing
      ? await freeConfigImportName(data.name, (candidate) => isNameTaken(context, user, settingsType, candidate, options), { maxLength: FINTEL_TEMPLATE_NAME_MAX_LENGTH })
      : data.name;
    if (!name) {
      return refused('failed', 'name_conflict', 'Fintel template name already exists', !!existing, data);
    }
    reservedNames?.add(fintelTemplateImportKey(settingsType, name));
    const reason = name === data.name ? undefined : `Added as "${configImportReasonValue(name)}"`;
    if (!dryRun) {
      await createFintelTemplate(context, user, data, widgets, {
        name,
        isDefault: !existing && data.default === true,
        standardId: existing ? undefined : data.standard_id,
      });
    }
    return { status: 'created', exists: !!existing, configuration: data, copyName: name, reason };
  }
  if (!existing) {
    reservedNames?.add(fintelTemplateImportKey(settingsType, data.name));
    if (!dryRun) {
      await createFintelTemplate(context, user, data, widgets, { name: data.name, isDefault: data.default === true, standardId: data.standard_id });
    }
    return { status: 'created', exists: false, configuration: data };
  }
  // The entity type of a template is never edited: the same template is never one of another type
  if (existing.settings_types?.[0] !== settingsType) {
    return refused('failed', 'entity_type', 'The entity type of the fintel template cannot change', true, data);
  }
  const patch = buildPatch(existing, data, widgets);
  if (patch.length === 0) {
    return refused('skipped', 'unchanged', CONFIG_IMPORT_UNCHANGED_REASON, true, data);
  }
  reservedNames?.add(fintelTemplateImportKey(settingsType, data.name));
  if (data.name !== existing.name) {
    renamedIds?.add(existing.id);
  }
  if (!dryRun) {
    await fintelTemplateEditField(context, user, existing.id, patch);
  }
  return { status: 'overwritten', exists: true, configuration: data };
};
