import { FintelTemplateOrdering } from '../../../generated/graphql';
import { fullEntitiesList, pageEntitiesConnection } from '../../../database/middleware-loader';
import { ConfigImportMode } from '../../configImport/configImport-types';
import { exportFintelTemplateToBundle } from '../../fintelTemplate/fintelTemplate-export';
import { importFintelTemplate } from '../../fintelTemplate/fintelTemplate-import';
import { FINTEL_TEMPLATE_STANDARD_ID_PATTERN } from '../../fintelTemplate/fintelTemplate-import-schema';
import { type BasicStoreEntityFintelTemplate, ENTITY_TYPE_FINTEL_TEMPLATE } from '../../fintelTemplate/fintelTemplate-types';
import type { ConfigPresetFamilyDefinition, ConfigPresetItemDefinition } from '../configPreset-types';
import type { ConfigPresetComputedItem, ConfigPresetImporter } from '../import/configPreset-import-types';
import { buildConfigPresetConnection, customizationGroup, standardIdListArgs, toAppliedItem, toComputedItem } from './common-configPreset-registry';

export const FINTEL_TEMPLATES_FAMILY_ID = 'fintelTemplates';

// The family is part of the Enterprise Edition: the registry reads the templates only once the license is checked, through the loaders,
// and the domain checks it again when a template is written
const fintelTemplatesArgs = (ids?: string[] | null, excludedIds?: string[] | null) => ({
  orderBy: FintelTemplateOrdering.Name,
  ...standardIdListArgs(ids, excludedIds),
});

// What an item is called: every entity type has its own templates, the built-in ones of the same name included, so the type is said too
const fintelTemplateLabel = (name: unknown, settingsTypes: unknown, fallback: string) => {
  if (typeof name !== 'string' || !name.trim()) {
    return fallback;
  }
  const [settingsType] = Array.isArray(settingsTypes) ? settingsTypes : [];
  return typeof settingsType === 'string' && settingsType.trim() ? `${name.trim()} (${settingsType.trim()})` : name.trim();
};

// A template is identified by its standard id. It is random: the same in the bundle and on the platform it comes from, not on another one.
// The default template of an entity type is marked, and selected like any other: no template depends on it. When it is exported, the platform
// the bundle is imported to gets it as the default of that type.
const toFintelTemplateItem = (template: BasicStoreEntityFintelTemplate): ConfigPresetItemDefinition => ({
  id: template.standard_id,
  label: fintelTemplateLabel(template.name, template.settings_types, template.standard_id),
  translatable: false,
  isDefault: template.default === true,
  dependsOn: [],
  exporter: async (context, user) => exportFintelTemplateToBundle(context, user, template),
});

const fintelTemplatesImporter: ConfigPresetImporter = {
  compute: async (context, user, item, plan, mode): Promise<ConfigPresetComputedItem> => {
    const { name, settings_types: settingsTypes } = item.configuration;
    const label = { label: fintelTemplateLabel(name, settingsTypes, item.id), translatable: false };
    const isDefault = item.configuration.default === true;
    // The bundle id of a template is its standard id
    if (!FINTEL_TEMPLATE_STANDARD_ID_PATTERN.test(item.id) || item.configuration.standard_id !== item.id) {
      return { ...label, isDefault, exists: false, conflict: false, status: 'failed', reason: 'The standard id of the fintel template does not match its id' };
    }
    // The names of the earlier items are reserved in the preview only, whose plan holds them: a real import reads the platform
    const result = await importFintelTemplate(context, user, item.configuration, {
      mode,
      dryRun: true,
      reservedNames: plan.fintelTemplateNames,
      renamedIds: plan.renamedFintelTemplateIds,
    });
    return { ...toComputedItem(label, result), isDefault };
  },
  apply: async (context, user, item, computed, mode) => toAppliedItem(await importFintelTemplate(context, user, item.configuration, { mode }), computed),
};

// Fintel templates of every entity type, paged and searched through the loaders. An import overwrites, or adds a copy.
export const fintelTemplatesFamily: ConfigPresetFamilyDefinition = {
  importer: fintelTemplatesImporter,
  importModes: [ConfigImportMode.Overwrite, ConfigImportMode.Copy],
  requiresEnterpriseEdition: true,
  id: FINTEL_TEMPLATES_FAMILY_ID,
  label: 'Fintel templates',
  description: 'Fintel templates of the entity types and their widgets',
  group: customizationGroup,
  directory: 'customization/fintel_templates',
  // The fintel templates page of an entity type imports only the templates of that entity type
  scopeKey: 'settings_types',
  listItems: async (context, user, args) => {
    const { first, after, search, ids, excludedIds } = args;
    // An empty list of ids is no template: as a filter value it would match every template
    if (ids?.length === 0) {
      return buildConfigPresetConnection(args, [], 0, false);
    }
    const page = await pageEntitiesConnection<BasicStoreEntityFintelTemplate>(context, user, [ENTITY_TYPE_FINTEL_TEMPLATE], {
      first,
      after,
      search,
      ...fintelTemplatesArgs(ids, excludedIds),
    });
    const edges = page.edges.map(({ cursor, node }) => ({ cursor, node: toFintelTemplateItem(node) }));
    return buildConfigPresetConnection(args, edges, page.pageInfo.globalCount, page.pageInfo.hasNextPage);
  },
  resolveItems: async (context, user, ids, excludedIds) => {
    if (ids?.length === 0) {
      return [];
    }
    const templates = await fullEntitiesList<BasicStoreEntityFintelTemplate>(context, user, [ENTITY_TYPE_FINTEL_TEMPLATE], fintelTemplatesArgs(ids, excludedIds));
    return templates.map(toFintelTemplateItem);
  },
};
