import type { AuthContext, AuthUser } from '../../types/user';
import { toExportedFintelTemplateWidgets } from './fintelTemplate-domain';
import type { BasicStoreEntityFintelTemplate } from './fintelTemplate-types';
import type { FintelTemplateImportConfiguration } from './fintelTemplate-import-schema';

// A fintel template in the import format of a configuration bundle (fintelTemplate-import-schema): the configuration of the file export, with
// the standard id that identifies the template. Every key is written, empty or not: an overwrite then makes the template the one of the bundle,
// an empty description or a template that is not published included. The widgets point to what they filter by its standard id.
export const exportFintelTemplateToBundle = async (
  context: AuthContext,
  user: AuthUser,
  template: BasicStoreEntityFintelTemplate,
): Promise<FintelTemplateImportConfiguration> => ({
  standard_id: template.standard_id,
  name: template.name,
  settings_types: template.settings_types,
  description: template.description ?? '',
  instance_filters: template.instance_filters ?? null,
  template_content: template.template_content ?? '',
  start_date: template.start_date ?? null,
  fintel_template_widgets: await toExportedFintelTemplateWidgets(context, user, template.fintel_template_widgets ?? []),
  default: template.default === true,
  include_cover_page_by_default: template.include_cover_page_by_default ?? true,
  include_back_page_by_default: template.include_back_page_by_default ?? true,
});
