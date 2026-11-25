import { FormsOrdering } from '../../../generated/graphql';
import { ConfigImportMode } from '../../configImport/configImport-types';
import { findAllForms, findFormPaginated } from '../../form/form-domain';
import { exportFormIntake } from '../../form/form-export';
import { importFormIntake } from '../../form/form-import';
import type { BasicStoreEntityForm } from '../../form/form-types';
import type { ConfigPresetFamilyDefinition, ConfigPresetItemDefinition } from '../configPreset-types';
import type { ConfigPresetImporter } from '../import/configPreset-import-types';
import { buildConfigPresetConnection, integrationsGroup, standardIdListArgs, toAppliedStatus, toComputedItem } from './common-configPreset-registry';

export const FORM_INTAKES_FAMILY_ID = 'formIntakes';

const formIntakesArgs = (ids?: string[] | null, excludedIds?: string[] | null) => ({ orderBy: FormsOrdering.Name, ...standardIdListArgs(ids, excludedIds) });

// The bundle id of a form intake is its standard id, which is random: the same form has another one on every platform.
// It only tells the items of a bundle apart: a form is found on the platform that imports it by its name and its main entity type.
const toFormIntakeItem = (form: BasicStoreEntityForm): ConfigPresetItemDefinition => ({
  id: form.standard_id,
  label: form.name,
  translatable: false,
  isEnabled: form.active,
  exporter: async (context, user) => exportFormIntake(context, user, form),
});

const formIntakesImporter: ConfigPresetImporter = {
  compute: async (context, user, item, plan, mode) => {
    const { name } = item.configuration;
    const label = { label: typeof name === 'string' ? name.trim() : item.id, translatable: false };
    plan.formIntakeKeys ??= new Set();
    const result = await importFormIntake(context, user, item.configuration, { mode, dryRun: true, reservedKeys: plan.formIntakeKeys });
    // A form is created inactive, and an overwritten one is set inactive
    return { ...toComputedItem(label, result), isEnabled: result.status === 'created' || result.status === 'overwritten' ? false : null };
  },
  apply: async (context, user, item, computed, mode) => {
    return toAppliedStatus(await importFormIntake(context, user, item.configuration, { mode }), computed);
  },
};

// Form intakes with their schema, paged and searched through the form domain. An import creates them inactive, overwrites, or adds a copy under a free name.
export const formIntakesFamily: ConfigPresetFamilyDefinition = {
  importer: formIntakesImporter,
  importModes: [ConfigImportMode.Overwrite, ConfigImportMode.Copy],
  id: FORM_INTAKES_FAMILY_ID,
  label: 'Form intakes',
  description: 'Form intakes and their schema',
  group: integrationsGroup,
  directory: 'integrations/form_intakes',
  listItems: async (context, user, args) => {
    const { first, after, search, ids, excludedIds } = args;
    // An empty list of ids is no form: as a filter value it would match every form
    if (ids?.length === 0) {
      return buildConfigPresetConnection(args, [], 0, false);
    }
    const page = await findFormPaginated(context, user, { first, after, search, ...formIntakesArgs(ids, excludedIds) });
    const edges = page.edges.map(({ cursor, node }: { cursor: string; node: BasicStoreEntityForm }) => ({ cursor, node: toFormIntakeItem(node) }));
    return buildConfigPresetConnection(args, edges, page.pageInfo.globalCount, page.pageInfo.hasNextPage);
  },
  resolveItems: async (context, user, ids, excludedIds) => {
    if (ids?.length === 0) {
      return [];
    }
    const forms = await findAllForms(context, user, formIntakesArgs(ids, excludedIds));
    return forms.map(toFormIntakeItem);
  },
};
