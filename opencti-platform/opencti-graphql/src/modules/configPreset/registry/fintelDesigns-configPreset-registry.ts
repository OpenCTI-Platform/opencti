import { FintelDesignOrdering } from '../../../generated/graphql';
import { FunctionalError } from '../../../config/errors';
import type { AuthContext, AuthUser } from '../../../types/user';
import { ConfigImportMode } from '../../configImport/configImport-types';
import { fullEntitiesList, pageEntitiesConnection } from '../../../database/middleware-loader';
import { exportFintelDesign } from '../../fintelDesign/fintelDesign-export';
import { importFintelDesign } from '../../fintelDesign/fintelDesign-import';
import { FINTEL_DESIGN_STANDARD_ID_PATTERN } from '../../fintelDesign/fintelDesign-import-schema';
import { fintelDesignLogoExtension, readFintelDesignLogo } from '../../fintelDesign/fintelDesign-logo';
import { type BasicStoreEntityFintelDesign, ENTITY_TYPE_FINTEL_DESIGN } from '../../fintelDesign/fintelDesign-types';
import type { ConfigPresetFamilyDefinition, ConfigPresetItemDefinition } from '../configPreset-types';
import type { ConfigPresetComputedItem, ConfigPresetImporter } from '../import/configPreset-import-types';
import { buildConfigPresetConnection, customizationGroup, standardIdListArgs, toAppliedStatus } from './common-configPreset-registry';

export const FINTEL_DESIGNS_FAMILY_ID = 'fintelDesigns';

// The family is part of the Enterprise Edition: the registry reads the designs only once the license is checked, through the loaders,
// and the domain checks it again when a design is written
const fintelDesignsArgs = (ids?: string[] | null, excludedIds?: string[] | null) => ({
  orderBy: FintelDesignOrdering.Name,
  ...standardIdListArgs(ids, excludedIds),
});

const findDefaultFintelDesign = async (context: AuthContext, user: AuthUser) => {
  const [defaultDesign] = await fullEntitiesList<BasicStoreEntityFintelDesign>(context, user, [ENTITY_TYPE_FINTEL_DESIGN], {
    ...standardIdListArgs(null, null, [{ key: ['default'], values: [true as unknown as string] }]),
  });
  return defaultDesign;
};

// A design is identified by its standard id everywhere: it is the same on every platform the design is imported to.
// The default design is exported with any other design, whatever the selection: every other design depends on it, so that the platform the
// bundle is imported to gets the default design of the platform it was exported from.
// The logo is a file written next to the JSON of the design, named by its format: the stored file has no extension.
const toFintelDesignItem = (design: BasicStoreEntityFintelDesign, defaultDesignId: string | undefined): ConfigPresetItemDefinition => {
  const isDefault = design.standard_id === defaultDesignId;
  return {
    id: design.standard_id,
    label: design.name,
    translatable: false,
    isDefault,
    dependsOn: defaultDesignId && !isDefault ? [{ type: FINTEL_DESIGNS_FAMILY_ID, id: defaultDesignId }] : [],
    exporter: async () => exportFintelDesign(design),
    ...(design.file_id ? {
      attachment: {
        // The name is the only thing read before the bytes: the format of the logo is the one of the bytes, checked when they are read
        name: `${design.standard_id}.logo`,
        read: async () => {
          const content = await readFintelDesignLogo(design);
          if (!content || !fintelDesignLogoExtension(content)) {
            throw FunctionalError('The logo of a fintel design is not a supported image', { id: design.internal_id, name: design.name });
          }
          return content;
        },
      },
    } : {}),
  };
};

const fintelDesignsImporter: ConfigPresetImporter = {
  compute: async (context, user, item, plan, mode): Promise<ConfigPresetComputedItem> => {
    const { name } = item.configuration;
    const base = { label: typeof name === 'string' && name.trim() ? name : item.id, translatable: false, isDefault: item.configuration.default === true };
    // The bundle id of a design is its standard id
    if (!FINTEL_DESIGN_STANDARD_ID_PATTERN.test(item.id) || item.configuration.standard_id !== item.id) {
      return { ...base, exists: false, conflict: false, status: 'failed', reason: 'The standard id of the fintel design does not match its id' };
    }
    // The names of the earlier items are reserved in the preview only, whose plan holds them: a real import reads the platform
    const result = await importFintelDesign(context, user, item.configuration, item.attachment, {
      mode,
      dryRun: true,
      reservedNames: plan.fintelDesignNames,
      renamedIds: plan.renamedFintelDesignIds,
    });
    return { ...base, exists: result.exists, conflict: result.exists, status: result.status, reason: result.reason, code: result.code };
  },
  apply: async (context, user, item, computed, mode) => {
    return toAppliedStatus(await importFintelDesign(context, user, item.configuration, item.attachment, { mode }), computed);
  },
};

// Fintel designs with their logo, paged and searched through the loaders. An import overwrites, or adds a copy.
export const fintelDesignsFamily: ConfigPresetFamilyDefinition = {
  importer: fintelDesignsImporter,
  importModes: [ConfigImportMode.Overwrite, ConfigImportMode.Copy],
  requiresEnterpriseEdition: true,
  id: FINTEL_DESIGNS_FAMILY_ID,
  label: 'Fintel designs',
  description: 'Fintel designs, their colors and logos',
  group: customizationGroup,
  directory: 'customization/fintel_designs',
  listItems: async (context, user, args) => {
    const { first, after, search, ids, excludedIds } = args;
    // An empty list of ids is no design: as a filter value it would match every design
    if (ids?.length === 0) {
      return buildConfigPresetConnection(args, [], 0, false);
    }
    const [page, defaultDesign] = await Promise.all([
      pageEntitiesConnection<BasicStoreEntityFintelDesign>(context, user, [ENTITY_TYPE_FINTEL_DESIGN], { first, after, search, ...fintelDesignsArgs(ids, excludedIds) }),
      findDefaultFintelDesign(context, user),
    ]);
    const edges = page.edges.map(({ cursor, node }) => ({ cursor, node: toFintelDesignItem(node, defaultDesign?.standard_id) }));
    return buildConfigPresetConnection(args, edges, page.pageInfo.globalCount, page.pageInfo.hasNextPage);
  },
  resolveItems: async (context, user, ids, excludedIds) => {
    if (ids?.length === 0) {
      return [];
    }
    const [designs, defaultDesign] = await Promise.all([
      fullEntitiesList<BasicStoreEntityFintelDesign>(context, user, [ENTITY_TYPE_FINTEL_DESIGN], fintelDesignsArgs(ids, excludedIds)),
      findDefaultFintelDesign(context, user),
    ]);
    return designs.map((design) => toFintelDesignItem(design, defaultDesign?.standard_id));
  },
};
