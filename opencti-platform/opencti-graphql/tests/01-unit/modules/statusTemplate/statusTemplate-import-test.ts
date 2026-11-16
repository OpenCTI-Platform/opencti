import { beforeEach, describe, expect, it, vi } from 'vitest';

vi.mock('../../../../src/database/middleware-loader', async (importOriginal) => ({
  ...(await importOriginal<typeof import('../../../../src/database/middleware-loader')>()),
  storeLoadById: vi.fn(),
}));
vi.mock('../../../../src/domain/status', async (importOriginal) => ({
  ...(await importOriginal<typeof import('../../../../src/domain/status')>()),
  createStatusTemplate: vi.fn(),
  statusTemplateEditField: vi.fn(),
}));

import { storeLoadById } from '../../../../src/database/middleware-loader';
import { createStatusTemplate, statusTemplateEditField } from '../../../../src/domain/status';
import { ENTITY_TYPE_STATUS_TEMPLATE } from '../../../../src/schema/internalObject';
import { ConfigImportMode } from '../../../../src/modules/configImport/configImport-types';
import { getStatusTemplateStandardId, importStatusTemplate } from '../../../../src/modules/statusTemplate/statusTemplate-import';
import { statusTemplateImportSchema } from '../../../../src/modules/statusTemplate/statusTemplate-import-schema';
import { exportStatusTemplate } from '../../../../src/modules/statusTemplate/statusTemplate-export';
import type { BasicStoreEntityStatusTemplate } from '../../../../src/modules/statusTemplate/statusTemplate-types';
import type { AuthContext, AuthUser } from '../../../../src/types/user';

const context = { source: 'test' } as AuthContext;
const user = { id: 'user-id' } as AuthUser;
const stored = { id: 'template-internal-id', standard_id: getStatusTemplateStandardId('Escalated'), name: 'Escalated', color: '#e91e63' } as BasicStoreEntityStatusTemplate;

const withExisting = (template?: BasicStoreEntityStatusTemplate) => vi.mocked(storeLoadById).mockResolvedValue(template as never);

beforeEach(() => {
  vi.resetAllMocks();
  withExisting(undefined);
});

describe('Status template identity', () => {
  it('derives the standard id from the name, whatever its case and surrounding spaces', () => {
    expect(getStatusTemplateStandardId('Escalated')).toMatch(/^statustemplate--[0-9a-f-]{36}$/);
    expect(getStatusTemplateStandardId(' ESCALATED ')).toBe(getStatusTemplateStandardId('Escalated'));
    expect(getStatusTemplateStandardId('IN_PROGRESS')).not.toBe(getStatusTemplateStandardId('NEW'));
  });
});

describe('Status template import schema', () => {
  it('accepts a name and a color, and trims the name', () => {
    expect(statusTemplateImportSchema.parse({ name: ' Escalated ', color: '#e91e63' })).toEqual({ name: 'Escalated', color: '#e91e63' });
    expect(statusTemplateImportSchema.parse({ name: 'New', color: '#fff' })).toEqual({ name: 'New', color: '#fff' });
  });

  it.each([
    [{}],
    [{ name: 'Escalated' }],
    [{ color: '#e91e63' }],
    [{ name: '   ', color: '#e91e63' }],
    // Shorter than the platform accepts for a status template (StatusTemplateAddInput)
    [{ name: 'E', color: '#e91e63' }],
    [{ name: 'Escalated', color: 'red' }],
    [{ name: 'Escalated', color: null }],
    [{ name: 'Escalated', color: '#e91e63', usages: 3 }],
    [{ name: 'Escalated', color: '#e91e63', standard_id: 'statustemplate--x' }],
  ])('refuses %j', (configuration) => {
    expect(statusTemplateImportSchema.safeParse(configuration).success).toBe(false);
  });

  it('is the format of the export, so an export imports back as is, without the usages', () => {
    const configuration = exportStatusTemplate({ ...stored, usages: 4, creator_id: ['secret'] } as unknown as BasicStoreEntityStatusTemplate);
    expect(configuration).toEqual({ name: 'Escalated', color: '#e91e63' });
    expect(statusTemplateImportSchema.safeParse(configuration).success).toBe(true);
  });
});

describe('importStatusTemplate', () => {
  it('refuses an invalid configuration with the path of each issue, without reading the platform', async () => {
    const result = await importStatusTemplate(context, user, { name: '', color: 'red' }, { mode: ConfigImportMode.Overwrite });
    expect(result).toMatchObject({ status: 'failed', code: 'invalid', exists: false });
    expect(result.reason).toContain('name: Status template name must be at least 2 characters');
    expect(result.reason).toContain('color: Must be a hex color');
    expect(storeLoadById).not.toHaveBeenCalled();
  });

  it('finds the template by its standard id, so the case of the name does not matter', async () => {
    await importStatusTemplate(context, user, { name: 'escalated', color: '#e91e63' }, { mode: ConfigImportMode.Overwrite, dryRun: true });
    expect(storeLoadById).toHaveBeenCalledWith(context, user, getStatusTemplateStandardId('Escalated'), ENTITY_TYPE_STATUS_TEMPLATE);
  });

  describe.each([ConfigImportMode.Overwrite, ConfigImportMode.Add])('a template that does not exist (%s)', (mode) => {
    it('creates it with its name and color', async () => {
      expect(await importStatusTemplate(context, user, { name: 'Escalated', color: '#e91e63' }, { mode })).toMatchObject({ status: 'created', exists: false });
      expect(createStatusTemplate).toHaveBeenCalledWith(context, user, { name: 'Escalated', color: '#e91e63' });
    });

    it('decides the same result on a dry run, and writes nothing', async () => {
      expect(await importStatusTemplate(context, user, { name: 'Escalated', color: '#e91e63' }, { mode, dryRun: true })).toMatchObject({ status: 'created', exists: false });
      expect(createStatusTemplate).not.toHaveBeenCalled();
    });
  });

  describe('a template that exists, overwrite', () => {
    beforeEach(() => withExisting(stored));

    it('gives it the color of the configuration', async () => {
      expect(await importStatusTemplate(context, user, { name: 'Escalated', color: '#00ff00' }, { mode: ConfigImportMode.Overwrite })).toMatchObject({ status: 'overwritten', exists: true });
      expect(statusTemplateEditField).toHaveBeenCalledWith(context, user, stored.id, [{ key: 'color', value: ['#00ff00'] }]);
      expect(createStatusTemplate).not.toHaveBeenCalled();
    });

    it('writes nothing on a dry run', async () => {
      expect(await importStatusTemplate(context, user, { name: 'Escalated', color: '#00ff00' }, { mode: ConfigImportMode.Overwrite, dryRun: true })).toMatchObject({ status: 'overwritten' });
      expect(statusTemplateEditField).not.toHaveBeenCalled();
    });

    it('skips it when it has the same color, whatever its case, as the templates of a new instance do', async () => {
      expect(await importStatusTemplate(context, user, { name: 'ESCALATED', color: '#E91E63' }, { mode: ConfigImportMode.Overwrite }))
        .toMatchObject({ status: 'skipped', code: 'unchanged', exists: true, reason: 'Already up to date' });
      expect(statusTemplateEditField).not.toHaveBeenCalled();
    });
  });

  it('refuses a template that exists when the mode is add', async () => {
    withExisting(stored);
    expect(await importStatusTemplate(context, user, { name: 'Escalated', color: '#00ff00' }, { mode: ConfigImportMode.Add })).toMatchObject({ status: 'failed', code: 'exists', exists: true });
    expect(statusTemplateEditField).not.toHaveBeenCalled();
  });

  it('has no copy: a status template is its name', async () => {
    const configuration = { name: 'Escalated', color: '#e91e63' };
    withExisting(stored);
    expect(await importStatusTemplate(context, user, configuration, { mode: ConfigImportMode.Copy })).toMatchObject({ status: 'failed', code: 'copy_unsupported', exists: true });
    withExisting(undefined);
    expect(await importStatusTemplate(context, user, configuration, { mode: ConfigImportMode.Copy })).toMatchObject({ status: 'failed', code: 'copy_unsupported', exists: false });
    expect(createStatusTemplate).not.toHaveBeenCalled();
    expect(statusTemplateEditField).not.toHaveBeenCalled();
  });
});
