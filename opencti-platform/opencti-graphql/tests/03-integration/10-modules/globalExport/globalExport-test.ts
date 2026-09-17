import { describe, it, expect, vi } from 'vitest';
import { ZipArchive } from 'archiver';
import {
  exportCategory,
  exportCustomViewsCategory,
  exportDashboardsCategory,
  exportFintelTemplatesCategory,
  exportFormsCategory,
  exportHiddenEntityTypesCategory,
  exportIngestionCsvCategory,
  exportIngestionJsonCategory,
  exportIngestionRssCategory,
  exportIngestionTaxiiCategory,
  exportPlaybooksCategory,
  exportSettingsBrandingCategory,
  exportSettingsLanguageCategory,
  exportSettingsMessagesCategory,
  exportSettingsThemeCategory,
  generateGlobalConfigurationExport,
  SETTINGS_BRANDING,
  SETTINGS_HIDDEN_ENTITY_TYPES,
  SETTINGS_LANGUAGE,
  SETTINGS_MESSAGES,
  SETTINGS_THEME,
} from '../../../../src/modules/globalExport/globalExport-domain';
import { getSettings } from '../../../../src/domain/settings';
import { ADMIN_USER, testContext } from '../../../utils/testQuery';
import { ENTITY_TYPE_PLAYBOOK } from '../../../../src/modules/playbook/playbook-types';
import { ENTITY_TYPE_FORM } from '../../../../src/modules/form/form-types';
import { ENTITY_TYPE_INGESTION_CSV, ENTITY_TYPE_INGESTION_JSON, ENTITY_TYPE_INGESTION_RSS, ENTITY_TYPE_INGESTION_TAXII } from '../../../../src/modules/ingestion/ingestion-types';
import { ENTITY_TYPE_WORKSPACE } from '../../../../src/modules/workspace/workspace-types';
import { ENTITY_TYPE_CUSTOM_VIEW } from '../../../../src/modules/customView/customView-types';
import { ENTITY_TYPE_FINTEL_TEMPLATE } from '../../../../src/modules/fintelTemplate/fintelTemplate-types';
import { fullEntitiesList } from '../../../../src/database/middleware-loader';

const createFakeArchive = () => ({ append: vi.fn() }) as unknown as ZipArchive;

const ZIP_MAGIC_BYTES = Buffer.from([0x50, 0x4b, 0x03, 0x04]);

describe('Global configuration export', () => {
  describe('category functions', () => {
    it('should export existing playbooks and append one entry per playbook', async () => {
      const archive = createFakeArchive();
      const count = await exportPlaybooksCategory(testContext, ADMIN_USER, archive);

      expect(count).toBeGreaterThanOrEqual(0);
      expect(archive.append).toHaveBeenCalledTimes(count);
      if (count > 0) {
        const [content, options] = (archive.append as ReturnType<typeof vi.fn>).mock.calls[0];
        expect(typeof content).toBe('string');
        expect(options.name).toMatch(/^playbooks\/playbook-.+\.json$/);
      }
    });

    it('should export existing forms and append one entry per form', async () => {
      const archive = createFakeArchive();
      const count = await exportFormsCategory(testContext, ADMIN_USER, archive);

      expect(archive.append).toHaveBeenCalledTimes(count);
      if (count > 0) {
        const [, options] = (archive.append as ReturnType<typeof vi.fn>).mock.calls[0];
        expect(options.name).toMatch(/^form_intakes\/form-.+\.json$/);
      }
    });

    it('should export existing dashboards and append one entry per dashboard', async () => {
      const archive = createFakeArchive();
      const count = await exportDashboardsCategory(testContext, ADMIN_USER, archive);

      expect(count).toBeGreaterThanOrEqual(0);
      expect(archive.append).toHaveBeenCalledTimes(count);
      if (count > 0) {
        const [, options] = (archive.append as ReturnType<typeof vi.fn>).mock.calls[0];
        expect(options.name).toMatch(/^dashboards\/dash-.+\.json$/);
      }
    });

    it('should export existing custom views and append one entry per custom view', async () => {
      const archive = createFakeArchive();
      const count = await exportCustomViewsCategory(testContext, ADMIN_USER, archive);

      expect(archive.append).toHaveBeenCalledTimes(count);
      if (count > 0) {
        const [, options] = (archive.append as ReturnType<typeof vi.fn>).mock.calls[0];
        expect(options.name).toMatch(/^custom_views\/custom-view-.+\.json$/);
      }
    });

    it('should export existing fintel templates and append one entry per template', async () => {
      const archive = createFakeArchive();
      const count = await exportFintelTemplatesCategory(testContext, ADMIN_USER, archive);

      expect(archive.append).toHaveBeenCalledTimes(count);
      if (count > 0) {
        const [, options] = (archive.append as ReturnType<typeof vi.fn>).mock.calls[0];
        expect(options.name).toMatch(/^fintel_templates\/fintel-template-.+\.json$/);
      }
    });

    it('should export existing CSV ingestion feeds and append one entry per feed', async () => {
      const archive = createFakeArchive();
      const count = await exportIngestionCsvCategory(testContext, ADMIN_USER, archive);

      expect(archive.append).toHaveBeenCalledTimes(count);
      if (count > 0) {
        const [, options] = (archive.append as ReturnType<typeof vi.fn>).mock.calls[0];
        expect(options.name).toMatch(/^ingestion\/feeds\/feed-csv\/feed-csv-.+\.json$/);
      }
    });

    it('should export existing JSON ingestion feeds and append one entry per feed', async () => {
      const archive = createFakeArchive();
      const count = await exportIngestionJsonCategory(testContext, ADMIN_USER, archive);

      expect(archive.append).toHaveBeenCalledTimes(count);
      if (count > 0) {
        const [, options] = (archive.append as ReturnType<typeof vi.fn>).mock.calls[0];
        expect(options.name).toMatch(/^ingestion\/feeds\/feed-json\/feed-json-.+\.json$/);
      }
    });

    it('should export existing RSS ingestion feeds and append one entry per feed', async () => {
      const archive = createFakeArchive();
      const count = await exportIngestionRssCategory(testContext, ADMIN_USER, archive);

      expect(archive.append).toHaveBeenCalledTimes(count);
      if (count > 0) {
        const [, options] = (archive.append as ReturnType<typeof vi.fn>).mock.calls[0];
        expect(options.name).toMatch(/^ingestion\/feeds\/feed-rss\/feed-rss-.+\.json$/);
      }
    });

    it('should export existing TAXII ingestion feeds and append one entry per feed', async () => {
      const archive = createFakeArchive();
      const count = await exportIngestionTaxiiCategory(testContext, ADMIN_USER, archive);

      expect(archive.append).toHaveBeenCalledTimes(count);
      if (count > 0) {
        const [, options] = (archive.append as ReturnType<typeof vi.fn>).mock.calls[0];
        expect(options.name).toMatch(/^ingestion\/feeds\/feed-taxii\/feed-taxii-.+\.json$/);
      }
    });

    it('should export platform branding settings as a single settings/branding.json entry', async () => {
      const archive = createFakeArchive();
      const settings = await getSettings(testContext) as any;
      const count = await exportSettingsBrandingCategory(testContext, ADMIN_USER, archive);

      expect(count).toBe(1);
      expect(archive.append).toHaveBeenCalledTimes(1);
      const [content, options] = (archive.append as ReturnType<typeof vi.fn>).mock.calls[0];
      expect(options.name).toBe('settings/branding.json');
      const parsed = JSON.parse(content);
      expect(parsed.type).toBe('settingsBranding');
      expect(parsed).toHaveProperty('openCTI_version');

      expect(parsed.configuration.platform_title).toEqual(settings.platform_title);
      expect(parsed.configuration.platform_favicon).toEqual(settings.platform_favicon);
      expect(parsed.configuration.platform_whitemark).toEqual(settings.platform_whitemark);
      expect(parsed.configuration.platform_map_tile_server_dark).toEqual(settings.platform_map_tile_server_dark);
      expect(parsed.configuration.platform_map_tile_server_light).toEqual(settings.platform_map_tile_server_light);

      // Credentials / env-specific fields must never leak into the export
      expect(parsed.configuration).not.toHaveProperty('platform_email');
      expect(parsed.configuration).not.toHaveProperty('local_auth');
      expect(parsed.configuration).not.toHaveProperty('cert_auth');
      expect(parsed.configuration).not.toHaveProperty('headers_auth');
    });

    it('should export the platform theme as a single settings/theme.json entry with flattened Theme fields', async () => {
      const archive = createFakeArchive();
      const settings = await getSettings(testContext);
      const count = await exportSettingsThemeCategory(testContext, ADMIN_USER, archive);

      expect(count).toBe(1);
      expect(archive.append).toHaveBeenCalledTimes(1);
      const [content, options] = (archive.append as ReturnType<typeof vi.fn>).mock.calls[0];
      expect(options.name).toBe('settings/theme.json');
      const parsed = JSON.parse(content);
      expect(parsed.type).toBe('settingsTheme');

      const theme = settings.platform_theme;
      expect(parsed.configuration.name).toEqual(theme.name);
      expect(parsed.configuration.theme_background).toEqual(theme.theme_background);
      expect(parsed.configuration.theme_paper).toEqual(theme.theme_paper);
      expect(parsed.configuration.theme_nav).toEqual(theme.theme_nav);
      expect(parsed.configuration.theme_primary).toEqual(theme.theme_primary);
      expect(parsed.configuration.theme_secondary).toEqual(theme.theme_secondary);
      expect(parsed.configuration.theme_accent).toEqual(theme.theme_accent);
      expect(parsed.configuration.theme_logo).toEqual(theme.theme_logo);
      expect(parsed.configuration.theme_logo_collapsed).toEqual(theme.theme_logo_collapsed);
      expect(parsed.configuration.theme_logo_login).toEqual(theme.theme_logo_login);
      expect(parsed.configuration.theme_text_color).toEqual(theme.theme_text_color);
      expect(parsed.configuration.theme_login_aside_color).toEqual(theme.theme_login_aside_color);
      expect(parsed.configuration.theme_login_aside_gradient_start).toEqual(theme.theme_login_aside_gradient_start);
      expect(parsed.configuration.theme_login_aside_gradient_end).toEqual(theme.theme_login_aside_gradient_end);
      expect(parsed.configuration.theme_login_aside_image).toEqual(theme.theme_login_aside_image);
      expect(parsed.configuration.built_in).toEqual(theme.built_in);

      // Internal identifiers must never leak into the export
      expect(parsed.configuration).not.toHaveProperty('id');
      expect(parsed.configuration).not.toHaveProperty('standard_id');
      expect(parsed.configuration).not.toHaveProperty('internal_id');
    });

    it('should export language settings as a single settings/language.json entry', async () => {
      const archive = createFakeArchive();
      const settings = await getSettings(testContext) as any;
      const count = await exportSettingsLanguageCategory(testContext, ADMIN_USER, archive);

      expect(count).toBe(1);
      expect(archive.append).toHaveBeenCalledTimes(1);
      const [content, options] = (archive.append as ReturnType<typeof vi.fn>).mock.calls[0];
      expect(options.name).toBe('settings/language.json');
      const parsed = JSON.parse(content);
      expect(parsed.type).toBe('settingsLanguage');
      expect(parsed.configuration.platform_language).toEqual(settings.platform_language);
      expect(parsed.configuration.platform_translations).toEqual(settings.platform_translations);
    });

    it('should export message settings as a single settings/messages.json entry', async () => {
      const archive = createFakeArchive();
      const settings = await getSettings(testContext) as any;
      const count = await exportSettingsMessagesCategory(testContext, ADMIN_USER, archive);

      expect(count).toBe(1);
      expect(archive.append).toHaveBeenCalledTimes(1);
      const [content, options] = (archive.append as ReturnType<typeof vi.fn>).mock.calls[0];
      expect(options.name).toBe('settings/messages.json');
      const parsed = JSON.parse(content);
      expect(parsed.type).toBe('settingsMessages');
      expect(parsed.configuration.platform_banner_text).toEqual(settings.platform_banner_text);
      expect(parsed.configuration.platform_banner_level).toEqual(settings.platform_banner_level);
      expect(parsed.configuration.platform_login_message).toEqual(settings.platform_login_message);
      expect(parsed.configuration.platform_consent_message).toEqual(settings.platform_consent_message);
      expect(parsed.configuration.platform_consent_confirm_text).toEqual(settings.platform_consent_confirm_text);
      expect(parsed.configuration.platform_no_access_message).toEqual(settings.platform_no_access_message);
    });

    it('should export hidden entity types as a single entity_settings/hidden_entity_types.json entry', async () => {
      const archive = createFakeArchive();
      const count = await exportHiddenEntityTypesCategory(testContext, ADMIN_USER, archive);

      expect(count).toBeGreaterThanOrEqual(0);
      expect(archive.append).toHaveBeenCalledTimes(1);
      const [content, options] = (archive.append as ReturnType<typeof vi.fn>).mock.calls[0];
      expect(options.name).toBe('entity_settings/hidden_entity_types.json');
      const parsed = JSON.parse(content);
      expect(parsed.type).toBe('settingsHiddenEntityTypes');
      expect(Array.isArray(parsed.configuration.hidden_entity_types)).toBe(true);
      expect(parsed.configuration.hidden_entity_types.length).toBe(count);
    });
  });

  describe('exportCategory dispatch', () => {
    it('should route ENTITY_TYPE_PLAYBOOK to the playbook category export', async () => {
      const archive = createFakeArchive();
      const count = await exportCategory(testContext, ADMIN_USER, ENTITY_TYPE_PLAYBOOK, archive);
      expect(count).toBeGreaterThanOrEqual(0);
    });

    it('should throw on an unknown entity_type', async () => {
      const archive = createFakeArchive();
      await expect(
        exportCategory(testContext, ADMIN_USER, 'NotARealEntityType', archive),
      ).rejects.toThrow('Unknown configuration export entity_type: "NotARealEntityType"');
    });

    it('should route ENTITY_TYPE_WORKSPACE to the dashboards category export', async () => {
      const archive = createFakeArchive();
      const count = await exportCategory(testContext, ADMIN_USER, ENTITY_TYPE_WORKSPACE, archive);
      expect(count).toBeGreaterThanOrEqual(0);
    });

    it('should route ENTITY_TYPE_CUSTOM_VIEW to the custom views category export', async () => {
      const archive = createFakeArchive();
      const count = await exportCategory(testContext, ADMIN_USER, ENTITY_TYPE_CUSTOM_VIEW, archive);
      expect(count).toBeGreaterThanOrEqual(0);
    });

    it('should route ENTITY_TYPE_FINTEL_TEMPLATE to the fintel templates category export', async () => {
      const archive = createFakeArchive();
      const count = await exportCategory(testContext, ADMIN_USER, ENTITY_TYPE_FINTEL_TEMPLATE, archive);
      expect(count).toBeGreaterThanOrEqual(0);
    });

    it('should route ENTITY_TYPE_INGESTION_CSV to the CSV ingestion category export', async () => {
      const archive = createFakeArchive();
      const count = await exportCategory(testContext, ADMIN_USER, ENTITY_TYPE_INGESTION_CSV, archive);
      expect(count).toBeGreaterThanOrEqual(0);
    });

    it('should route ENTITY_TYPE_INGESTION_JSON to the JSON ingestion category export', async () => {
      const archive = createFakeArchive();
      const count = await exportCategory(testContext, ADMIN_USER, ENTITY_TYPE_INGESTION_JSON, archive);
      expect(count).toBeGreaterThanOrEqual(0);
    });

    it('should route ENTITY_TYPE_INGESTION_RSS to the RSS ingestion category export', async () => {
      const archive = createFakeArchive();
      const count = await exportCategory(testContext, ADMIN_USER, ENTITY_TYPE_INGESTION_RSS, archive);
      expect(count).toBeGreaterThanOrEqual(0);
    });

    it('should route ENTITY_TYPE_INGESTION_TAXII to the TAXII ingestion category export', async () => {
      const archive = createFakeArchive();
      const count = await exportCategory(testContext, ADMIN_USER, ENTITY_TYPE_INGESTION_TAXII, archive);
      expect(count).toBeGreaterThanOrEqual(0);
    });

    it('should route SETTINGS_BRANDING to the settings branding category export', async () => {
      const archive = createFakeArchive();
      const count = await exportCategory(testContext, ADMIN_USER, SETTINGS_BRANDING, archive);
      expect(count).toBe(1);
    });

    it('should route SETTINGS_THEME to the settings theme category export', async () => {
      const archive = createFakeArchive();
      const count = await exportCategory(testContext, ADMIN_USER, SETTINGS_THEME, archive);
      expect(count).toBe(1);
    });

    it('should route SETTINGS_LANGUAGE to the settings language category export', async () => {
      const archive = createFakeArchive();
      const count = await exportCategory(testContext, ADMIN_USER, SETTINGS_LANGUAGE, archive);
      expect(count).toBe(1);
    });

    it('should route SETTINGS_MESSAGES to the settings messages category export', async () => {
      const archive = createFakeArchive();
      const count = await exportCategory(testContext, ADMIN_USER, SETTINGS_MESSAGES, archive);
      expect(count).toBe(1);
    });

    it('should route SETTINGS_HIDDEN_ENTITY_TYPES to the hidden entity types category export', async () => {
      const archive = createFakeArchive();
      const count = await exportCategory(testContext, ADMIN_USER, SETTINGS_HIDDEN_ENTITY_TYPES, archive);
      expect(count).toBeGreaterThanOrEqual(0);
    });
  });

  describe('generateGlobalConfigurationExport', () => {
    it('should return a valid base64-encoded zip for the requested categories', async () => {
      const base64 = await generateGlobalConfigurationExport(testContext, ADMIN_USER, [
        ENTITY_TYPE_PLAYBOOK,
        ENTITY_TYPE_FORM,
      ]);

      expect(base64).toBeDefined();
      expect(typeof base64).toBe('string');

      const buffer = Buffer.from(base64, 'base64');
      expect(buffer.subarray(0, 4)).toEqual(ZIP_MAGIC_BYTES);
      expect(buffer.lastIndexOf(Buffer.from([0x50, 0x4b, 0x05, 0x06]))).toBeGreaterThan(0);
      expect(buffer.includes(Buffer.from('meta.json'))).toBe(true);
    });

    it('should deduplicate entity_types passed more than once', async () => {
      const base64 = await generateGlobalConfigurationExport(
        testContext,
        ADMIN_USER,
        [ENTITY_TYPE_FORM, ENTITY_TYPE_FORM],
      );
      expect(Buffer.from(base64, 'base64').subarray(0, 4)).toEqual(ZIP_MAGIC_BYTES);
    });

    it('should throw on an unknown entity_type', async () => {
      await expect(
        generateGlobalConfigurationExport(testContext, ADMIN_USER, ['NotARealEntityType']),
      ).rejects.toThrow('Unknown configuration export entity_type: "NotARealEntityType"');
    });

    it('should include all settings categories in a single bundle', async () => {
      const base64 = await generateGlobalConfigurationExport(testContext, ADMIN_USER, [
        SETTINGS_BRANDING,
        SETTINGS_THEME,
        SETTINGS_LANGUAGE,
        SETTINGS_MESSAGES,
        SETTINGS_HIDDEN_ENTITY_TYPES,
      ]);

      expect(base64).toBeDefined();
      const buffer = Buffer.from(base64, 'base64');
      expect(buffer.subarray(0, 4)).toEqual(ZIP_MAGIC_BYTES);
      expect(buffer.includes(Buffer.from('settings/branding.json'))).toBe(true);
      expect(buffer.includes(Buffer.from('settings/theme.json'))).toBe(true);
      expect(buffer.includes(Buffer.from('settings/language.json'))).toBe(true);
      expect(buffer.includes(Buffer.from('settings/messages.json'))).toBe(true);
      expect(buffer.includes(Buffer.from('entity_settings/hidden_entity_types.json'))).toBe(true);
      expect(buffer.includes(Buffer.from('meta.json'))).toBe(true);
    });
  });
  describe('id-based partial export (buildIdFilterGroup)', () => {
    it('should restrict playbook export to the given ids only', async () => {
      const all = await fullEntitiesList<any>(testContext, ADMIN_USER, [ENTITY_TYPE_PLAYBOOK], {});
      expect(Array.isArray(all)).toBe(true);
      if (all.length === 0) return;

      const target = all[0];
      const archive = createFakeArchive();
      const count = await exportPlaybooksCategory(testContext, ADMIN_USER, archive, [target.id]);

      expect(count).toBe(1);
      expect(archive.append).toHaveBeenCalledTimes(1);
      const [, options] = (archive.append as ReturnType<typeof vi.fn>).mock.calls[0];
      expect(options.name).toMatch(new RegExp(`^playbooks/playbook-.+-${target.id}\\.json$`));
    });

    it('should export nothing when given ids that do not match any playbook', async () => {
      const archive = createFakeArchive();
      const count = await exportPlaybooksCategory(testContext, ADMIN_USER, archive, ['not-a-real-id']);

      expect(count).toBe(0);
      expect(archive.append).not.toHaveBeenCalled();
    });

    it('should behave like "no filter" when ids is an empty array', async () => {
      const withoutFilterArchive = createFakeArchive();
      const withoutFilterCount = await exportFormsCategory(testContext, ADMIN_USER, withoutFilterArchive);

      const emptyIdsArchive = createFakeArchive();
      const emptyIdsCount = await exportFormsCategory(testContext, ADMIN_USER, emptyIdsArchive, []);

      expect(emptyIdsCount).toBe(withoutFilterCount);
    });

    it('should restrict form export to the given ids only', async () => {
      const all = await fullEntitiesList<any>(testContext, ADMIN_USER, [ENTITY_TYPE_FORM], {});
      if (all.length === 0) return;

      const target = all[0];
      const archive = createFakeArchive();
      const count = await exportFormsCategory(testContext, ADMIN_USER, archive, [target.id]);

      expect(count).toBe(1);
      const [, options] = (archive.append as ReturnType<typeof vi.fn>).mock.calls[0];
      expect(options.name).toMatch(new RegExp(`^form_intakes/form-.+-${target.id}\\.json$`));
    });

    it('should restrict custom views export to the given ids only', async () => {
      const all = await fullEntitiesList<any>(testContext, ADMIN_USER, [ENTITY_TYPE_CUSTOM_VIEW], {});
      if (all.length === 0) return;

      const target = all[0];
      const archive = createFakeArchive();
      const count = await exportCustomViewsCategory(testContext, ADMIN_USER, archive, [target.id]);

      expect(count).toBe(1);
      const [, options] = (archive.append as ReturnType<typeof vi.fn>).mock.calls[0];
      expect(options.name).toMatch(new RegExp(`^custom_views/custom-view-.+-${target.id}\\.json$`));
    });

    it('should restrict fintel templates export to the given ids only', async () => {
      const all = await fullEntitiesList<any>(testContext, ADMIN_USER, [ENTITY_TYPE_FINTEL_TEMPLATE], {});
      if (all.length === 0) return;

      const target = all[0];
      const archive = createFakeArchive();
      const count = await exportFintelTemplatesCategory(testContext, ADMIN_USER, archive, [target.id]);

      expect(count).toBe(1);
      const [, options] = (archive.append as ReturnType<typeof vi.fn>).mock.calls[0];
      expect(options.name).toMatch(new RegExp(`^fintel_templates/fintel-template-.+-${target.id}\\.json$`));
    });

    it('should restrict CSV ingestion feed export to the given ids only', async () => {
      const all = await fullEntitiesList<any>(testContext, ADMIN_USER, [ENTITY_TYPE_INGESTION_CSV], {});
      if (all.length === 0) return;

      const target = all[0];
      const archive = createFakeArchive();
      const count = await exportIngestionCsvCategory(testContext, ADMIN_USER, archive, [target.id]);

      expect(count).toBe(1);
      const [, options] = (archive.append as ReturnType<typeof vi.fn>).mock.calls[0];
      expect(options.name).toMatch(new RegExp(`^ingestion/feeds/feed-csv/feed-csv-.+-${target.id}\\.json$`));
    });

    it('should restrict dashboard export to a given dashboard id', async () => {
      const allWorkspaces = await fullEntitiesList<any>(testContext, ADMIN_USER, [ENTITY_TYPE_WORKSPACE], {});
      const dashboards = allWorkspaces.filter((w) => w.type === 'dashboard');
      if (dashboards.length === 0) return;

      const target = dashboards[0];
      const archive = createFakeArchive();
      const count = await exportDashboardsCategory(testContext, ADMIN_USER, archive, [target.id]);

      expect(count).toBe(1);
      const [, options] = (archive.append as ReturnType<typeof vi.fn>).mock.calls[0];
      expect(options.name).toMatch(new RegExp(`^dashboards/dash-.+-${target.id}\\.json$`));
    });

    // Regression test for the in-memory "type === 'dashboard'" filter combined with
    // the ES-level id filter: a non-dashboard workspace must be excluded even when
    // explicitly requested by id.
    it('should exclude a matched non-dashboard workspace even when explicitly requested by id', async () => {
      const allWorkspaces = await fullEntitiesList<any>(testContext, ADMIN_USER, [ENTITY_TYPE_WORKSPACE], {});
      const nonDashboard = allWorkspaces.find((w) => w.type !== 'dashboard');
      if (!nonDashboard) return;

      const archive = createFakeArchive();
      const count = await exportDashboardsCategory(testContext, ADMIN_USER, archive, [nonDashboard.id]);

      expect(count).toBe(0);
      expect(archive.append).not.toHaveBeenCalled();
    });
  });

  describe('exportCategory dispatch with ids', () => {
    it('should forward ids to the underlying category export when dispatching', async () => {
      const all = await fullEntitiesList<any>(testContext, ADMIN_USER, [ENTITY_TYPE_FORM], {});
      if (all.length === 0) return;
      const target = all[0];

      const archive = createFakeArchive();
      const count = await exportCategory(testContext, ADMIN_USER, ENTITY_TYPE_FORM, archive, [target.id]);

      expect(count).toBe(1);
      expect(archive.append).toHaveBeenCalledTimes(1);
    });
  });

  describe('generateGlobalConfigurationExport - access control', () => {
    it('should throw ForbiddenAccess when the user does not have the BYPASS capability', async () => {
      const restrictedUser = { ...ADMIN_USER, capabilities: [] } as unknown as typeof ADMIN_USER;

      await expect(
        generateGlobalConfigurationExport(testContext, restrictedUser, [ENTITY_TYPE_FORM]),
      ).rejects.toThrow();
    });
  });

  describe('generateGlobalConfigurationExport - meta.json content', () => {
    it('should embed accurate meta.json (version, author, deduplicated entity_types, counts)', async () => {
      const appendSpy = vi.spyOn(ZipArchive.prototype, 'append');

      await generateGlobalConfigurationExport(testContext, ADMIN_USER, [
        ENTITY_TYPE_PLAYBOOK,
        ENTITY_TYPE_FORM,
        ENTITY_TYPE_PLAYBOOK, // duplicate on purpose
      ]);

      const metaCall = appendSpy.mock.calls.find(([, options]) => options?.name === 'meta.json');
      expect(metaCall).toBeDefined();

      const meta = JSON.parse(metaCall![0] as string);
      expect(meta.generated_by).toBe(ADMIN_USER.id);
      expect(meta.entity_types).toEqual([ENTITY_TYPE_PLAYBOOK, ENTITY_TYPE_FORM]); // deduplicated, order preserved
      expect(typeof meta.generated_at).toBe('string');
      expect(new Date(meta.generated_at).toString()).not.toBe('Invalid Date');
      expect(meta.counts).toHaveProperty(ENTITY_TYPE_PLAYBOOK);
      expect(meta.counts).toHaveProperty(ENTITY_TYPE_FORM);
      expect(meta.requested_counts).toEqual({});

      appendSpy.mockRestore();
    });

    it('should populate requested_counts only for entity_types with an explicit id selection', async () => {
      const forms = await fullEntitiesList<any>(testContext, ADMIN_USER, [ENTITY_TYPE_FORM], {});
      if (forms.length === 0) return;
      const target = forms[0];

      const appendSpy = vi.spyOn(ZipArchive.prototype, 'append');

      await generateGlobalConfigurationExport(
        testContext,
        ADMIN_USER,
        [ENTITY_TYPE_FORM, ENTITY_TYPE_PLAYBOOK],
        [{ entityType: ENTITY_TYPE_FORM, ids: [target.id] }],
      );

      const metaCall = appendSpy.mock.calls.find(([, options]) => options?.name === 'meta.json');
      const meta = JSON.parse(metaCall![0] as string);

      expect(meta.requested_counts).toEqual({ [ENTITY_TYPE_FORM]: 1 });
      expect(meta.counts[ENTITY_TYPE_FORM]).toBe(1);

      appendSpy.mockRestore();
    });

    it('should ignore a selection whose ids array is empty', async () => {
      const appendSpy = vi.spyOn(ZipArchive.prototype, 'append');

      await generateGlobalConfigurationExport(
        testContext,
        ADMIN_USER,
        [ENTITY_TYPE_FORM],
        [{ entityType: ENTITY_TYPE_FORM, ids: [] }],
      );

      const metaCall = appendSpy.mock.calls.find(([, options]) => options?.name === 'meta.json');
      const meta = JSON.parse(metaCall![0] as string);

      expect(meta.requested_counts).toEqual({});

      appendSpy.mockRestore();
    });

    it('should produce a valid zip containing only meta.json when entityTypes is empty', async () => {
      const base64 = await generateGlobalConfigurationExport(testContext, ADMIN_USER, []);
      const buffer = Buffer.from(base64, 'base64');

      expect(buffer.subarray(0, 4)).toEqual(ZIP_MAGIC_BYTES);
      expect(buffer.includes(Buffer.from('meta.json'))).toBe(true);
    });
  });
});
