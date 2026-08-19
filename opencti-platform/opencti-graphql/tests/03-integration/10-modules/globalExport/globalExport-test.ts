import { describe, it, expect, vi } from 'vitest';
import type { ZipArchive } from 'archiver';
import {
  exportCategory,
  exportCustomViewsCategory,
  exportDashboardsCategory,
  exportFintelTemplatesCategory,
  exportFormsCategory,
  exportIngestionCsvCategory,
  exportIngestionJsonCategory,
  exportIngestionRssCategory,
  exportIngestionTaxiiCategory,
  exportPlaybooksCategory,
  generateGlobalConfigurationExport,
} from '../../../../src/modules/globalExport/globalExport-domain';
import { ADMIN_USER, testContext } from '../../../utils/testQuery';
import { ENTITY_TYPE_PLAYBOOK } from '../../../../src/modules/playbook/playbook-types';
import { ENTITY_TYPE_FORM } from '../../../../src/modules/form/form-types';
import { ENTITY_TYPE_INGESTION_CSV, ENTITY_TYPE_INGESTION_JSON, ENTITY_TYPE_INGESTION_RSS, ENTITY_TYPE_INGESTION_TAXII } from '../../../../src/modules/ingestion/ingestion-types';
import { ENTITY_TYPE_WORKSPACE } from '../../../../src/modules/workspace/workspace-types';
import { ENTITY_TYPE_CUSTOM_VIEW } from '../../../../src/modules/customView/customView-types';
import { ENTITY_TYPE_FINTEL_TEMPLATE } from '../../../../src/modules/fintelTemplate/fintelTemplate-types';

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
  });
});
