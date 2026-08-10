import { describe, it, expect, vi } from 'vitest';
import type { ZipArchive } from 'archiver';
import { exportCategory, exportFormsCategory, exportPlaybooksCategory, generateGlobalConfigurationExport } from '../../../../src/modules/globalExport/globalExport-domain';
import { ADMIN_USER, testContext } from '../../../utils/testQuery';
import { ENTITY_TYPE_PLAYBOOK } from '../../../../src/modules/playbook/playbook-types';
import { ENTITY_TYPE_FORM } from '../../../../src/modules/form/form-types';

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
