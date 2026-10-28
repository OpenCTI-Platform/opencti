import { beforeEach, describe, expect, it, vi } from 'vitest';

vi.mock('../../../../src/modules/theme/theme-domain', () => ({
  addTheme: vi.fn(),
  checkExistingTheme: vi.fn(),
  fieldPatchTheme: vi.fn(),
  findById: vi.fn(),
}));
vi.mock('../../../../src/utils/fileToContent', () => ({ extractContentFrom: vi.fn() }));

import { addTheme, checkExistingTheme, fieldPatchTheme, findById } from '../../../../src/modules/theme/theme-domain';
import { importTheme, themeImport } from '../../../../src/modules/theme/theme-import';
import { BUILT_IN_THEME_STANDARD_IDS } from '../../../../src/modules/theme/theme-constants';
import { extractContentFrom } from '../../../../src/utils/fileToContent';
import type { AuthContext, AuthUser } from '../../../../src/types/user';
import { CUSTOM_THEME_ID, themeConfiguration } from '../../../utils/configPresetBundle';

const context = { source: 'test' } as AuthContext;
const user = { id: 'user-id' } as AuthUser;
const createdTheme = { id: 'created-id', name: 'Import test theme' };
const patchedTheme = { id: 'existing-id', name: 'Import test theme' };

// A theme file has no standard id
const themeFileContent = (overrides: Record<string, unknown> = {}) => themeConfiguration({ standard_id: undefined, ...overrides });

beforeEach(() => {
  vi.resetAllMocks();
  vi.mocked(findById).mockResolvedValue(undefined as never);
  vi.mocked(checkExistingTheme).mockResolvedValue(false);
  vi.mocked(addTheme).mockResolvedValue(createdTheme as never);
  vi.mocked(fieldPatchTheme).mockResolvedValue(patchedTheme as never);
});

const expectNothingWritten = () => {
  expect(addTheme).not.toHaveBeenCalled();
  expect(fieldPatchTheme).not.toHaveBeenCalled();
};

describe('importTheme validation', () => {
  it.each([
    ['an unknown key', { built_in: true }],
    ['a relative logo', { theme_logo: '/static/logo.png' }],
    ['a logo that is not http(s)', { theme_logo: 'javascript:alert(1)' }],
    ['a background image with a forbidden character', { theme_login_aside_image: 'https://example.com/a.png);color:red' }],
    ['a colour that is not hex', { theme_primary: 'rgb(0, 0, 0)' }],
    ['a missing name', { name: '' }],
  ])('refuses %s, in every mode, without writing', async (_, overrides) => {
    const configuration = themeConfiguration(overrides);
    const results = await Promise.all([
      importTheme(context, user, configuration, { mode: 'add' }),
      importTheme(context, user, configuration, { mode: 'overwrite' }),
    ]);
    results.forEach((result) => expect(result).toMatchObject({ status: 'failed', code: 'invalid', exists: false, configuration: undefined }));
    expectNothingWritten();
  });

  it('accepts an http or https URL for the logos and the background image, and hex colours', async () => {
    const configuration = themeConfiguration({
      theme_logo: 'http://example.com/a.png',
      theme_logo_collapsed: 'https://example.com/b.png',
      theme_logo_login: '',
      theme_login_aside_image: 'http://example.com/d.jpg',
      theme_login_aside_color: '#aabbcc80',
    });
    expect(await importTheme(context, user, configuration, { mode: 'overwrite', dryRun: true })).toMatchObject({ status: 'created' });
  });

  it('gives the reason of each invalid value', async () => {
    const result = await importTheme(context, user, themeConfiguration({ theme_primary: 'red', theme_logo: '/a.png' }), { mode: 'add' });
    expect(result.reason).toContain('theme_primary: Must be a hex color');
    expect(result.reason).toContain('theme_logo');
  });
});

describe('importTheme in add mode', () => {
  it('creates a theme without standard id, the platform gives it one, and the logos default to empty', async () => {
    const result = await importTheme(context, user, themeFileContent({ theme_logo: undefined }), { mode: 'add' });
    expect(result).toMatchObject({ status: 'created', exists: false, theme: createdTheme });
    expect(findById).not.toHaveBeenCalled();
    const input = vi.mocked(addTheme).mock.calls[0][2];
    expect(input).toMatchObject({ name: 'Import test theme', theme_logo: '', theme_logo_collapsed: '', theme_logo_login: '', built_in: false });
    expect(input).not.toHaveProperty('standard_id');
  });

  it('creates a theme with the standard id it comes with', async () => {
    await importTheme(context, user, themeConfiguration(), { mode: 'add' });
    expect(vi.mocked(addTheme).mock.calls[0][2]).toMatchObject({ standard_id: CUSTOM_THEME_ID, built_in: false });
  });

  it('refuses a theme whose standard id exists', async () => {
    vi.mocked(findById).mockResolvedValue({ id: 'existing-id', built_in: false } as never);
    expect(await importTheme(context, user, themeConfiguration(), { mode: 'add' })).toMatchObject({ status: 'failed', code: 'exists', exists: true });
    expectNothingWritten();
  });

  it('refuses a name that another theme uses', async () => {
    vi.mocked(checkExistingTheme).mockResolvedValue(true);
    expect(await importTheme(context, user, themeFileContent(), { mode: 'add' })).toMatchObject({ status: 'failed', code: 'name_conflict', reason: 'Theme name already exists' });
    expectNothingWritten();
  });
});

describe('importTheme in overwrite mode', () => {
  it('requires the standard id', async () => {
    expect(await importTheme(context, user, themeFileContent(), { mode: 'overwrite' })).toMatchObject({ status: 'failed', code: 'standard_id_required' });
    expectNothingWritten();
  });

  it('creates the theme when its standard id is absent from the platform', async () => {
    const result = await importTheme(context, user, themeConfiguration(), { mode: 'overwrite' });
    expect(result).toMatchObject({ status: 'created', exists: false, theme: createdTheme });
    expect(findById).toHaveBeenCalledWith(context, user, CUSTOM_THEME_ID);
    expect(fieldPatchTheme).not.toHaveBeenCalled();
  });

  it('patches the existing theme with the values that are set, a null or absent one is left untouched', async () => {
    vi.mocked(findById).mockResolvedValue({ id: 'existing-id', built_in: false } as never);
    const result = await importTheme(context, user, themeConfiguration({ theme_login_aside_color: null, theme_logo: undefined }), { mode: 'overwrite' });
    expect(result).toMatchObject({ status: 'overwritten', exists: true, theme: patchedTheme });
    expect(addTheme).not.toHaveBeenCalled();
    const [, , id, input] = vi.mocked(fieldPatchTheme).mock.calls[0];
    expect(id).toBe('existing-id');
    expect(input).toContainEqual({ key: 'name', value: ['Import test theme'] });
    expect(input).toContainEqual({ key: 'theme_primary', value: ['#ff0000'] });
    expect(input.map(({ key }) => key)).not.toContain('theme_login_aside_color');
    expect(input.map(({ key }) => key)).not.toContain('theme_logo');
    expect(input.map(({ key }) => key)).not.toContain('standard_id');
  });

  it('does not take the theme itself for a name conflict, but refuses a name of another theme', async () => {
    vi.mocked(findById).mockResolvedValue({ id: 'existing-id', built_in: false } as never);
    await importTheme(context, user, themeConfiguration(), { mode: 'overwrite' });
    expect(checkExistingTheme).toHaveBeenCalledWith(context, user, 'Import test theme', 'existing-id');
    vi.mocked(checkExistingTheme).mockResolvedValue(true);
    vi.mocked(fieldPatchTheme).mockClear();
    expect(await importTheme(context, user, themeConfiguration(), { mode: 'overwrite' })).toMatchObject({ status: 'failed', code: 'name_conflict', exists: true });
    expect(fieldPatchTheme).not.toHaveBeenCalled();
  });

  it('skips a built-in theme without looking it up, and a theme the platform flags as built-in', async () => {
    const [standardId] = Object.values(BUILT_IN_THEME_STANDARD_IDS);
    expect(await importTheme(context, user, themeConfiguration({ standard_id: standardId }), { mode: 'overwrite' }))
      .toMatchObject({ status: 'skipped', code: 'built_in', exists: true, reason: 'Built-in theme' });
    expect(findById).not.toHaveBeenCalled();
    vi.mocked(findById).mockResolvedValue({ id: 'existing-id', built_in: true } as never);
    expect(await importTheme(context, user, themeConfiguration(), { mode: 'overwrite' })).toMatchObject({ status: 'skipped', code: 'built_in' });
    expectNothingWritten();
  });
});

describe('importTheme dry run', () => {
  it('decides the same status as the import, and writes nothing', async () => {
    const created = await importTheme(context, user, themeConfiguration(), { mode: 'overwrite', dryRun: true });
    expect(created).toMatchObject({ status: 'created', exists: false });
    expect(created.theme).toBeUndefined();
    vi.mocked(findById).mockResolvedValue({ id: 'existing-id', built_in: false } as never);
    const overwritten = await importTheme(context, user, themeConfiguration(), { mode: 'overwrite', dryRun: true });
    expect(overwritten).toMatchObject({ status: 'overwritten', exists: true });
    expect(overwritten.theme).toBeUndefined();
    vi.mocked(checkExistingTheme).mockResolvedValue(true);
    expect(await importTheme(context, user, themeConfiguration(), { mode: 'overwrite', dryRun: true })).toMatchObject({ status: 'failed', code: 'name_conflict' });
    expectNothingWritten();
  });
});

describe('themeImport (theme file)', () => {
  const file = Promise.resolve({}) as never;

  it('creates the theme of the file and returns it', async () => {
    vi.mocked(extractContentFrom).mockResolvedValue(themeFileContent());
    expect(await themeImport(context, user, file)).toBe(createdTheme);
    expect(vi.mocked(addTheme).mock.calls[0][2]).toMatchObject({ name: 'Import test theme', built_in: false });
  });

  it('refuses an invalid file with its reasons', async () => {
    vi.mocked(extractContentFrom).mockResolvedValue(themeFileContent({ theme_logo: '/static/logo.png', extra: 1 }));
    await expect(themeImport(context, user, file)).rejects.toMatchObject({
      message: 'Invalid theme file',
      extensions: { data: { reason: expect.stringContaining('theme_logo') } },
    });
    expectNothingWritten();
  });

  it('refuses a name that another theme uses', async () => {
    vi.mocked(extractContentFrom).mockResolvedValue(themeFileContent());
    vi.mocked(checkExistingTheme).mockResolvedValue(true);
    await expect(themeImport(context, user, file)).rejects.toThrow('Theme name already exists');
    expectNothingWritten();
  });

  it('refuses a file of a theme that exists', async () => {
    vi.mocked(extractContentFrom).mockResolvedValue(themeConfiguration());
    vi.mocked(findById).mockResolvedValue({ id: 'existing-id', built_in: false } as never);
    await expect(themeImport(context, user, file)).rejects.toThrow('Theme already exists');
    expectNothingWritten();
  });
});
