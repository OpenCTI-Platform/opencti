import { Readable } from 'node:stream';
import { beforeEach, describe, expect, it, vi } from 'vitest';

vi.mock('../../../../src/database/middleware-loader', async (importOriginal) => ({
  ...(await importOriginal<typeof import('../../../../src/database/middleware-loader')>()),
  storeLoadById: vi.fn(),
  fullEntitiesList: vi.fn(),
}));
vi.mock('../../../../src/database/middleware', async (importOriginal) => ({
  ...(await importOriginal<typeof import('../../../../src/database/middleware')>()),
  updateAttribute: vi.fn(),
}));
vi.mock('../../../../src/domain/internalObject', async (importOriginal) => ({
  ...(await importOriginal<typeof import('../../../../src/domain/internalObject')>()),
  createInternalObject: vi.fn(),
}));
vi.mock('../../../../src/database/redis', async (importOriginal) => ({
  ...(await importOriginal<typeof import('../../../../src/database/redis')>()),
  redisUpdateExclusionListStatus: vi.fn(),
  notify: vi.fn(),
}));
vi.mock('../../../../src/database/file-storage', async (importOriginal) => ({
  ...(await importOriginal<typeof import('../../../../src/database/file-storage')>()),
  uploadToStorage: vi.fn(),
}));
vi.mock('../../../../src/listener/UserActionListener', async (importOriginal) => ({
  ...(await importOriginal<typeof import('../../../../src/listener/UserActionListener')>()),
  publishUserAction: vi.fn(),
}));

import { fullEntitiesList, storeLoadById } from '../../../../src/database/middleware-loader';
import { updateAttribute } from '../../../../src/database/middleware';
import { createInternalObject } from '../../../../src/domain/internalObject';
import { notify, redisUpdateExclusionListStatus } from '../../../../src/database/redis';
import { uploadToStorage } from '../../../../src/database/file-storage';
import { publishUserAction } from '../../../../src/listener/UserActionListener';
import { addExclusionListFile, exclusionListStorageKey, fieldPatchExclusionList, findExclusionListsByName } from '../../../../src/modules/exclusionList/exclusionList-domain';
import type { AuthContext, AuthUser } from '../../../../src/types/user';
import { dnsExclusionList } from '../configPreset/configPreset-exclusionLists-fixtures';

const context = { source: 'test' } as AuthContext;
const user = { id: 'user-id' } as AuthUser;
const upload = (filename = 'values.txt', content = '8.8.8.8\n') => ({ createReadStream: () => Readable.from([Buffer.from(content)]), filename, mimeType: 'text/plain' });

beforeEach(() => {
  vi.resetAllMocks();
  vi.mocked(storeLoadById).mockResolvedValue(dnsExclusionList as never);
  vi.mocked(updateAttribute).mockResolvedValue({ element: dnsExclusionList } as never);
  vi.mocked(createInternalObject).mockResolvedValue({ id: 'created' } as never);
  vi.mocked(uploadToStorage).mockImplementation(async (_context, _user, filePath, file) => ({ upload: { id: `${filePath}/${(await file).filename.toLowerCase()}` } }) as never);
});

describe('Exclusion list domain', () => {
  describe('the cache of the lists', () => {
    const patch = (input: { key: string; value: string[] }[], file?: ReturnType<typeof upload>) => {
      return fieldPatchExclusionList(context, user, { id: dnsExclusionList.id, input, file: file as never });
    };

    it.each([
      ['a rename', [{ key: 'name', value: ['Renamed'] }]],
      ['a new description', [{ key: 'description', value: ['Another one'] }]],
      // The edit form sends the types on every save, whatever the field that was edited
      ['the same types sent again by the edit form', [{ key: 'name', value: ['Renamed'] }, { key: 'exclusion_list_entity_types', value: ['IPv4-Addr'] }]],
    ])('is not asked to rebuild for %s', async (_name, input) => {
      await patch(input);
      expect(redisUpdateExclusionListStatus).not.toHaveBeenCalled();
    });

    it.each([
      ['other types', [{ key: 'exclusion_list_entity_types', value: ['IPv6-Addr'] }]],
      ['more types', [{ key: 'exclusion_list_entity_types', value: ['IPv4-Addr', 'IPv6-Addr'] }]],
      ['the state', [{ key: 'enabled', value: ['false'] }]],
    ])('is asked to rebuild for %s', async (_name, input) => {
      await patch(input);
      expect(redisUpdateExclusionListStatus).toHaveBeenCalledTimes(1);
    });

    it('is asked to rebuild for new values, even when nothing else is sent', async () => {
      await patch([], upload());
      expect(redisUpdateExclusionListStatus).toHaveBeenCalledTimes(1);
    });
  });

  describe('the audit of an update', () => {
    const message = () => (vi.mocked(publishUserAction).mock.calls[0][0] as { message: string }).message;

    it('lists the fields that are sent', async () => {
      await fieldPatchExclusionList(context, user, { id: dnsExclusionList.id, input: [{ key: 'name', value: ['Renamed'] }, { key: 'description', value: ['x'] }] });
      expect(message()).toBe('updates `name, description` for exclusion list `Public DNS resolvers`');
    });

    it('names the file when the values are sent, with or without fields', async () => {
      await fieldPatchExclusionList(context, user, { id: dnsExclusionList.id, input: [], file: upload() as never });
      expect(message()).toBe('updates `file` for exclusion list `Public DNS resolvers`');
      vi.mocked(publishUserAction).mockClear();
      await fieldPatchExclusionList(context, user, { id: dnsExclusionList.id, input: [{ key: 'name', value: ['Renamed'] }], file: upload() as never });
      expect(message()).toBe('updates `name, file` for exclusion list `Public DNS resolvers`');
    });
  });

  describe('the creation of a list', () => {
    const input = (name: string) => ({ name, exclusion_list_entity_types: ['IPv4-Addr'], file: upload() as never });

    it.each([[''], ['   '], ['D'], [' D ']])('refuses the name %j, whatever the way the list is created, before anything is stored', async (name) => {
      await expect(addExclusionListFile(context, user, input(name))).rejects.toThrow('Exclusion list name must have at least 2 characters');
      expect(uploadToStorage).not.toHaveBeenCalled();
      expect(createInternalObject).not.toHaveBeenCalled();
    });

    it('accepts a name of two characters', async () => {
      await addExclusionListFile(context, user, input('DN'));
      expect(createInternalObject).toHaveBeenCalledTimes(1);
    });

    it('stores the file of a list under the key the export reads it from, and that key is the file_id of the list', async () => {
      await addExclusionListFile(context, user, input('DNS'));
      const created = vi.mocked(createInternalObject).mock.calls[0][2] as { internal_id: string; file_id: string };
      expect(created.file_id).toBe(exclusionListStorageKey(created.internal_id));
    });
  });

  describe('the rename of a list', () => {
    it.each([[''], ['D'], [' D ']])('refuses the name %j, like the creation does, before anything is stored', async (name) => {
      await expect(fieldPatchExclusionList(context, user, { id: dnsExclusionList.id, input: [{ key: 'name', value: [name] }], file: upload() as never }))
        .rejects.toThrow('Exclusion list name must have at least 2 characters');
      expect(uploadToStorage).not.toHaveBeenCalled();
      expect(updateAttribute).not.toHaveBeenCalled();
    });

    it('refuses a short name sent after a valid one, as the last one is the one stored', async () => {
      const input = [{ key: 'name', value: ['Valid'] }, { key: 'name', value: ['X'] }];
      await expect(fieldPatchExclusionList(context, user, { id: dnsExclusionList.id, input })).rejects.toThrow('Exclusion list name must have at least 2 characters');
      expect(updateAttribute).not.toHaveBeenCalled();
    });

    it('accepts a name of two characters, and a patch without name', async () => {
      await fieldPatchExclusionList(context, user, { id: dnsExclusionList.id, input: [{ key: 'name', value: ['DN'] }] });
      await fieldPatchExclusionList(context, user, { id: dnsExclusionList.id, input: [{ key: 'description', value: ['x'] }] });
      expect(updateAttribute).toHaveBeenCalledTimes(2);
    });
  });

  describe('the lookup of a list by its name', () => {
    it('filters on the name on the index, and compares the name again without its case', async () => {
      vi.mocked(fullEntitiesList).mockResolvedValue([dnsExclusionList, { ...dnsExclusionList, name: 'public dns resolvers 2' }] as never);
      const found = await findExclusionListsByName(context, user, 'PUBLIC DNS Resolvers');
      expect(found).toEqual([dnsExclusionList]);
      expect(fullEntitiesList).toHaveBeenCalledWith(context, user, ['ExclusionList'], {
        filters: { mode: 'and', filters: [{ key: ['name'], values: ['PUBLIC DNS Resolvers'] }], filterGroups: [] },
      });
    });
  });

  it('notifies the edition of the list', async () => {
    await fieldPatchExclusionList(context, user, { id: dnsExclusionList.id, input: [] });
    expect(notify).toHaveBeenCalledTimes(1);
  });
});
