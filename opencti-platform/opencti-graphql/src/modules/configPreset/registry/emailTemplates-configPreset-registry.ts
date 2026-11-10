import { EmailTemplateOrdering } from '../../../generated/graphql';
import { findAllEmailTemplates, findEmailTemplatePaginated } from '../../emailTemplate/emailTemplate-domain';
import { exportEmailTemplate } from '../../emailTemplate/emailTemplate-export';
import { importEmailTemplate } from '../../emailTemplate/emailTemplate-import';
import type { BasicStoreEntityEmailTemplate } from '../../emailTemplate/emailTemplate-types';
import { ConfigImportMode } from '../../configImport/configImport-types';
import type { ConfigPresetFamilyDefinition, ConfigPresetItemDefinition } from '../configPreset-types';
import type { ConfigPresetImporter } from '../import/configPreset-import-types';
import { buildConfigPresetConnection, securityAccessGroup, standardIdListArgs, toAppliedStatus, toComputedItem } from './common-configPreset-registry';

export const EMAIL_TEMPLATES_FAMILY_ID = 'emailTemplates';

const emailTemplatesArgs = (ids?: string[] | null, excludedIds?: string[] | null) => ({ orderBy: EmailTemplateOrdering.Name, ...standardIdListArgs(ids, excludedIds) });

// The standard id of an email template is random: it is the same in the bundle and on the platform it comes from, not on another one
const toEmailTemplateItem = (emailTemplate: BasicStoreEntityEmailTemplate): ConfigPresetItemDefinition => ({
  id: emailTemplate.standard_id,
  label: emailTemplate.name,
  translatable: false,
  exporter: async () => exportEmailTemplate(emailTemplate),
});

const emailTemplatesImporter: ConfigPresetImporter = {
  // The bundle id cannot be checked against the content: the template is matched by its name, not by its id
  compute: async (context, user, item, plan, mode) => {
    const { name } = item.configuration;
    const label = { label: typeof name === 'string' && name.trim() ? name : item.id, translatable: false };
    const result = await importEmailTemplate(context, user, item.configuration, { mode, dryRun: true, reservedNames: plan.emailTemplateNames });
    return toComputedItem(label, result);
  },
  apply: async (context, user, item, computed, mode) => {
    return toAppliedStatus(await importEmailTemplate(context, user, item.configuration, { mode }), computed);
  },
};

// Email templates: paged and searched through the email template domain. An import matches a template by its name: it overwrites it, or adds a copy of it under a free name.
export const emailTemplatesFamily: ConfigPresetFamilyDefinition = {
  importer: emailTemplatesImporter,
  importModes: [ConfigImportMode.Overwrite, ConfigImportMode.Copy],
  id: EMAIL_TEMPLATES_FAMILY_ID,
  label: 'Email templates',
  description: 'Email templates and their content',
  group: securityAccessGroup,
  directory: 'security_access/email_templates',
  requiresEnterpriseEdition: true,
  listItems: async (context, user, args) => {
    const { first, after, search, ids, excludedIds } = args;
    // An empty list of ids is no template: as a filter value it would match every template
    if (ids?.length === 0) {
      return buildConfigPresetConnection(args, [], 0, false);
    }
    const page = await findEmailTemplatePaginated(context, user, { first, after, search, ...emailTemplatesArgs(ids, excludedIds) });
    const edges = page.edges.map(({ cursor, node }) => ({ cursor, node: toEmailTemplateItem(node) }));
    return buildConfigPresetConnection(args, edges, page.pageInfo.globalCount, page.pageInfo.hasNextPage);
  },
  resolveItems: async (context, user, ids, excludedIds) => {
    if (ids?.length === 0) {
      return [];
    }
    const emailTemplates = await findAllEmailTemplates(context, user, emailTemplatesArgs(ids, excludedIds));
    return emailTemplates.map(toEmailTemplateItem);
  },
};
