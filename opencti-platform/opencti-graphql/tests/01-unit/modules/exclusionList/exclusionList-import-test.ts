import { Readable } from 'node:stream';
import { beforeEach, describe, expect, it, vi } from 'vitest';

vi.mock('../../../../src/database/middleware-loader', async (importOriginal) => ({
  ...(await importOriginal<typeof import('../../../../src/database/middleware-loader')>()),
  fullEntitiesList: vi.fn(),
}));
vi.mock('../../../../src/modules/exclusionList/exclusionList-domain', async (importOriginal) => ({
  ...(await importOriginal<typeof import('../../../../src/modules/exclusionList/exclusionList-domain')>()),
  addExclusionListFile: vi.fn(),
  fieldPatchExclusionList: vi.fn(),
}));
vi.mock('../../../../src/modules/exclusionList/exclusionList-file', () => ({ readExclusionListFile: vi.fn() }));

import { fullEntitiesList } from '../../../../src/database/middleware-loader';
import { addExclusionListFile, fieldPatchExclusionList, MAX_FILE_SIZE } from '../../../../src/modules/exclusionList/exclusionList-domain';
import { readExclusionListFile } from '../../../../src/modules/exclusionList/exclusionList-file';
import { exportExclusionList } from '../../../../src/modules/exclusionList/exclusionList-export';
import { importExclusionList } from '../../../../src/modules/exclusionList/exclusionList-import';
import { exclusionListImportSchema } from '../../../../src/modules/exclusionList/exclusionList-import-schema';
import type { BasicStoreEntityExclusionList } from '../../../../src/modules/exclusionList/exclusionList-types';
import { ConfigImportMode } from '../../../../src/modules/configImport/configImport-types';
import type { AuthContext, AuthUser } from '../../../../src/types/user';
import { dnsExclusionList, retiredExclusionList } from '../configPreset/configPreset-exclusionLists-fixtures';

const context = { source: 'test' } as AuthContext;
const user = { id: 'user-id' } as AuthUser;
const configuration = { name: 'Public DNS resolvers', description: 'Well-known resolvers', enabled: true, exclusion_list_entity_types: ['IPv4-Addr'] };
const VALUES = Buffer.from('8.8.8.8\n1.1.1.1\n');
// A list of the platform that has the same values, the same size
const stored = { ...dnsExclusionList, exclusion_list_file_size: VALUES.length } as BasicStoreEntityExclusionList;
const fileOf = (content: Buffer | null) => ({ read: vi.fn().mockResolvedValue(content) });
const overwrite = { mode: ConfigImportMode.Overwrite };

const withLists = (...lists: BasicStoreEntityExclusionList[]) => vi.mocked(fullEntitiesList).mockResolvedValue(lists as never);
const readUpload = async (upload: unknown) => {
  const { createReadStream, filename, mimeType } = upload as { createReadStream: () => Readable; filename: string; mimeType: string };
  const chunks: Buffer[] = [];
  for await (const chunk of createReadStream()) {
    chunks.push(chunk as Buffer);
  }
  return { content: Buffer.concat(chunks), filename, mimeType };
};

beforeEach(() => {
  vi.resetAllMocks();
  withLists();
  vi.mocked(addExclusionListFile).mockResolvedValue({ id: 'new-list-id' } as never);
  vi.mocked(readExclusionListFile).mockResolvedValue(VALUES);
});

describe('Exclusion list import schema', () => {
  it('accepts a name and types with or without a description and a state, and trims the name', () => {
    expect(exclusionListImportSchema.parse({ name: ' DNS ', exclusion_list_entity_types: ['IPv4-Addr', 'IPv6-Addr'] })).toEqual({ name: 'DNS', exclusion_list_entity_types: ['IPv4-Addr', 'IPv6-Addr'] });
    expect(exclusionListImportSchema.parse(configuration)).toEqual(configuration);
    expect(exclusionListImportSchema.parse({ ...configuration, description: null })).toMatchObject({ description: null });
    expect(exclusionListImportSchema.parse({ name: 'D', exclusion_list_entity_types: ['Domain-Name', 'Hostname', 'Url', 'Email-Addr', 'StixFile', 'Artifact'] }).name).toBe('D');
  });

  it.each([
    [{}],
    [{ name: '   ', exclusion_list_entity_types: ['Url'] }],
    [{ name: 'DNS' }],
    [{ name: 'DNS', exclusion_list_entity_types: [] }],
    [{ name: 'DNS', exclusion_list_entity_types: ['Malware'] }],
    // The form refuses it: a list is checked either as addresses or as values
    [{ name: 'DNS', exclusion_list_entity_types: ['IPv4-Addr', 'Domain-Name'] }],
    [{ name: 'DNS', exclusion_list_entity_types: ['Url'], enabled: 'yes' }],
    [{ name: 'DNS', exclusion_list_entity_types: ['Url'], standard_id: 'x' }],
    [{ name: 'DNS', exclusion_list_entity_types: ['Url'], file_id: 'exclusionLists/x.txt' }],
  ])('refuses %j', (value) => {
    expect(exclusionListImportSchema.safeParse(value).success).toBe(false);
  });

  it('is the format of the export, so an export imports back as is, a disabled list without description included', () => {
    const exported = exportExclusionList({ ...dnsExclusionList, creator_id: ['secret'] } as BasicStoreEntityExclusionList);
    expect(exported).toEqual(configuration);
    expect(exclusionListImportSchema.safeParse(exported).success).toBe(true);
    const disabled = exportExclusionList(retiredExclusionList);
    expect(disabled).toEqual({ name: 'Retired partners', enabled: false, exclusion_list_entity_types: ['Domain-Name', 'Hostname'] });
    expect(exclusionListImportSchema.safeParse(disabled).success).toBe(true);
  });
});

describe('importExclusionList', () => {
  it('refuses an invalid configuration with the path of each issue, without reading the platform nor the file', async () => {
    const file = fileOf(VALUES);
    const result = await importExclusionList(context, user, { name: '', exclusion_list_entity_types: ['IPv4-Addr', 'Url'] }, file, overwrite);
    expect(result).toMatchObject({ status: 'failed', code: 'invalid', exists: false });
    expect(result.reason).toContain('name: Exclusion list name is required');
    expect(result.reason).toContain('exclusion_list_entity_types: IP types cannot be mixed with other types');
    expect(fullEntitiesList).not.toHaveBeenCalled();
    expect(file.read).not.toHaveBeenCalled();
  });

  describe.each([ConfigImportMode.Overwrite, ConfigImportMode.Add])('a list that does not exist (%s)', (mode) => {
    it('creates it with the types, the description and the values of the file, as a text file', async () => {
      const file = fileOf(VALUES);
      expect(await importExclusionList(context, user, configuration, file, { mode })).toMatchObject({ status: 'created', exists: false });
      expect(file.read).toHaveBeenCalledWith(MAX_FILE_SIZE);
      const [, , input] = vi.mocked(addExclusionListFile).mock.calls[0];
      expect(input).toMatchObject({ name: 'Public DNS resolvers', description: 'Well-known resolvers', exclusion_list_entity_types: ['IPv4-Addr'] });
      expect(await readUpload(input.file)).toEqual({ content: VALUES, filename: 'exclusion-list.txt', mimeType: 'text/plain' });
      // A new list is enabled: nothing more to write
      expect(fieldPatchExclusionList).not.toHaveBeenCalled();
    });

    it('creates it without description when the configuration has none', async () => {
      await importExclusionList(context, user, { name: 'DNS', exclusion_list_entity_types: ['IPv4-Addr'] }, fileOf(VALUES), { mode });
      expect(vi.mocked(addExclusionListFile).mock.calls[0][2]).toMatchObject({ name: 'DNS', description: undefined });
    });

    it('disables it once created when the configuration says so', async () => {
      await importExclusionList(context, user, { ...configuration, enabled: false }, fileOf(VALUES), { mode });
      expect(fieldPatchExclusionList).toHaveBeenCalledWith(context, user, { id: 'new-list-id', input: [{ key: 'enabled', value: ['false'] }] });
    });

    it('decides the same result on a dry run, and writes nothing', async () => {
      expect(await importExclusionList(context, user, configuration, fileOf(VALUES), { mode, dryRun: true })).toMatchObject({ status: 'created', exists: false });
      expect(addExclusionListFile).not.toHaveBeenCalled();
      expect(fieldPatchExclusionList).not.toHaveBeenCalled();
    });
  });

  it('lets a failed disabling surface, and a retry finds the list it created and disables it', async () => {
    vi.mocked(fieldPatchExclusionList).mockRejectedValueOnce(new Error('boom'));
    await expect(importExclusionList(context, user, { ...configuration, enabled: false }, fileOf(VALUES), overwrite)).rejects.toThrow('boom');
    expect(addExclusionListFile).toHaveBeenCalledTimes(1);
    // The list exists now, enabled, with the values of the bundle
    withLists({ ...stored, enabled: true } as BasicStoreEntityExclusionList);
    expect(await importExclusionList(context, user, { ...configuration, enabled: false }, fileOf(VALUES), overwrite)).toMatchObject({ status: 'overwritten' });
    expect(addExclusionListFile).toHaveBeenCalledTimes(1);
    expect(fieldPatchExclusionList).toHaveBeenLastCalledWith(context, user, { id: stored.id, input: [{ key: 'enabled', value: ['false'] }], file: undefined });
  });

  it('keeps the empty file of a list that has no value: the export of such a list imports back', async () => {
    expect(await importExclusionList(context, user, configuration, fileOf(Buffer.alloc(0)), overwrite)).toMatchObject({ status: 'created' });
    expect(await readUpload(vi.mocked(addExclusionListFile).mock.calls[0][2].file)).toMatchObject({ content: Buffer.alloc(0) });
  });

  describe('the file of the values', () => {
    it.each([
      ['does not exist', undefined],
      ['exists', stored],
    ])('refuses a list that %s when the bundle has no file for it, without writing', async (_name, existing) => {
      withLists(...(existing ? [existing] : []));
      expect(await importExclusionList(context, user, configuration, undefined, overwrite)).toMatchObject({ status: 'failed', code: 'file_missing', exists: !!existing });
      expect(addExclusionListFile).not.toHaveBeenCalled();
      expect(fieldPatchExclusionList).not.toHaveBeenCalled();
    });

    it.each([
      ['does not exist', undefined],
      ['exists', stored],
    ])('refuses a list that %s when the file is bigger than the limit of the platform, without writing', async (_name, existing) => {
      withLists(...(existing ? [existing] : []));
      const file = fileOf(null);
      expect(await importExclusionList(context, user, configuration, file, overwrite)).toMatchObject({ status: 'failed', code: 'file_too_large', exists: !!existing });
      expect(file.read).toHaveBeenCalledWith(MAX_FILE_SIZE);
      expect(addExclusionListFile).not.toHaveBeenCalled();
      expect(fieldPatchExclusionList).not.toHaveBeenCalled();
    });
  });

  describe('a list that exists', () => {
    beforeEach(() => withLists(stored));

    it('is found by its name, whatever its case and surrounding spaces', async () => {
      expect(await importExclusionList(context, user, { ...configuration, name: '  PUBLIC dns RESOLVERS ' }, fileOf(VALUES), overwrite)).toMatchObject({ status: 'skipped', exists: true });
      expect(addExclusionListFile).not.toHaveBeenCalled();
    });

    it('is refused in add mode, without writing', async () => {
      expect(await importExclusionList(context, user, configuration, fileOf(VALUES), { mode: ConfigImportMode.Add })).toMatchObject({ status: 'failed', code: 'exists', exists: true });
      expect(fieldPatchExclusionList).not.toHaveBeenCalled();
    });

    it('has no copy: an exclusion list is its name', async () => {
      expect(await importExclusionList(context, user, configuration, fileOf(VALUES), { mode: ConfigImportMode.Copy })).toMatchObject({ status: 'failed', code: 'copy_unsupported', exists: true });
      withLists();
      expect(await importExclusionList(context, user, configuration, fileOf(VALUES), { mode: ConfigImportMode.Copy })).toMatchObject({ status: 'failed', code: 'copy_unsupported', exists: false });
      expect(addExclusionListFile).not.toHaveBeenCalled();
      expect(fieldPatchExclusionList).not.toHaveBeenCalled();
    });

    it('is refused as ambiguous when several lists have its name, not guessed', async () => {
      withLists(stored, { ...retiredExclusionList, name: 'public dns resolvers' } as BasicStoreEntityExclusionList);
      expect(await importExclusionList(context, user, configuration, fileOf(VALUES), overwrite)).toMatchObject({ status: 'failed', code: 'ambiguous', exists: true });
      expect(fieldPatchExclusionList).not.toHaveBeenCalled();
    });

    it('is skipped as up to date when nothing differs, the order of the types and the description of the configuration aside', async () => {
      withLists({ ...stored, exclusion_list_entity_types: ['IPv4-Addr', 'IPv6-Addr'] } as BasicStoreEntityExclusionList);
      expect(await importExclusionList(context, user, { ...configuration, exclusion_list_entity_types: ['IPv6-Addr', 'IPv4-Addr'] }, fileOf(VALUES), overwrite))
        .toMatchObject({ status: 'skipped', code: 'unchanged', exists: true, reason: 'Already up to date' });
      expect(fieldPatchExclusionList).not.toHaveBeenCalled();
    });

    it('leaves the description and the state untouched when the configuration has none', async () => {
      expect(await importExclusionList(context, user, { name: 'Public DNS resolvers', exclusion_list_entity_types: ['IPv4-Addr'] }, fileOf(VALUES), overwrite)).toMatchObject({ status: 'skipped', code: 'unchanged' });
      expect(await importExclusionList(context, user, { ...configuration, description: null }, fileOf(VALUES), overwrite)).toMatchObject({ status: 'skipped', code: 'unchanged' });
      expect(fieldPatchExclusionList).not.toHaveBeenCalled();
    });

    it('is given the description, the state and the types of the configuration that differ, and not its file when it is the same', async () => {
      const result = await importExclusionList(context, user, { name: 'Public DNS resolvers', description: 'New', enabled: false, exclusion_list_entity_types: ['IPv4-Addr', 'IPv6-Addr'] }, fileOf(VALUES), overwrite);
      expect(result).toMatchObject({ status: 'overwritten', exists: true });
      expect(fieldPatchExclusionList).toHaveBeenCalledWith(context, user, {
        id: stored.id,
        input: [
          { key: 'description', value: ['New'] },
          { key: 'enabled', value: ['false'] },
          { key: 'exclusion_list_entity_types', value: ['IPv4-Addr', 'IPv6-Addr'] },
        ],
        file: undefined,
      });
    });

    it('gives an empty description to a list that has one', async () => {
      await importExclusionList(context, user, { ...configuration, description: '' }, fileOf(VALUES), overwrite);
      expect(vi.mocked(fieldPatchExclusionList).mock.calls[0][2].input).toEqual([{ key: 'description', value: [''] }]);
    });

    it('leaves a list that has no description as it is when the configuration gives an empty one', async () => {
      withLists({ ...stored, description: undefined } as unknown as BasicStoreEntityExclusionList);
      expect(await importExclusionList(context, user, { ...configuration, description: '' }, fileOf(VALUES), overwrite)).toMatchObject({ status: 'skipped', code: 'unchanged' });
      expect(fieldPatchExclusionList).not.toHaveBeenCalled();
    });

    it('is given the file when the values differ, whether the size differs or not', async () => {
      const changed = Buffer.from('8.8.8.8\n1.1.1.2\n');
      expect(changed.length).toBe(VALUES.length);
      const result = await importExclusionList(context, user, configuration, fileOf(changed), overwrite);
      expect(result).toMatchObject({ status: 'overwritten', exists: true });
      const args = vi.mocked(fieldPatchExclusionList).mock.calls[0][2];
      expect(args).toMatchObject({ id: stored.id, input: [] });
      expect(await readUpload(args.file)).toEqual({ content: changed, filename: 'exclusion-list.txt', mimeType: 'text/plain' });
      // The stored file is read only when the sizes are the same: it tells the other case apart for free
      vi.mocked(readExclusionListFile).mockClear();
      await importExclusionList(context, user, configuration, fileOf(Buffer.from('8.8.8.8\n')), overwrite);
      expect(readExclusionListFile).not.toHaveBeenCalled();
      expect(vi.mocked(fieldPatchExclusionList).mock.calls[1][2].file).toBeDefined();
    });

    it('is given the file when the platform has none stored for it', async () => {
      vi.mocked(readExclusionListFile).mockResolvedValue(null);
      expect(await importExclusionList(context, user, configuration, fileOf(VALUES), overwrite)).toMatchObject({ status: 'overwritten' });
      expect(vi.mocked(fieldPatchExclusionList).mock.calls[0][2].file).toBeDefined();
    });

    it('writes nothing on a dry run, and decides the same result', async () => {
      expect(await importExclusionList(context, user, { ...configuration, description: 'New' }, fileOf(VALUES), { ...overwrite, dryRun: true })).toMatchObject({ status: 'overwritten', exists: true });
      expect(await importExclusionList(context, user, configuration, fileOf(VALUES), { ...overwrite, dryRun: true })).toMatchObject({ status: 'skipped', code: 'unchanged' });
      expect(fieldPatchExclusionList).not.toHaveBeenCalled();
    });
  });
});
