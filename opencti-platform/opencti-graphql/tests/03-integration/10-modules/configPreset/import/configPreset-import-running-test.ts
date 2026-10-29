import { afterEach, describe, expect, it, vi } from 'vitest';
import gql from 'graphql-tag';
import { buildZip, validBundleFiles } from '../../../../utils/configPresetBundle';
import { createUploadFromBuffer, queryAsAdmin, queryAsAdminWithSuccess, queryAsUserIsExpectedForbidden } from '../../../../utils/testQueryHelper';
import { ADMIN_USER, testContext, USER_EDITOR } from '../../../../utils/testQuery';
import * as redisModule from '../../../../../src/database/redis';
import * as userDomain from '../../../../../src/modules/user/user-domain';
import {
  getClientBase,
  lockResource,
  redisDeleteConfigPresetImportRunning,
  redisGetConfigPresetImportLastFinished,
  redisGetConfigPresetImportRunning,
  redisSetConfigPresetImportRunning,
  redisUpdateConfigPresetImportRunning,
} from '../../../../../src/database/redis';
import { setPlatformBootstrapStatus } from '../../../../../src/domain/settings';
import { applyConfigPresetImportEvent } from '../../../../../src/modules/configPreset/import/configPreset-import-session-domain';
import { getConfigPresetPlatformId } from '../../../../../src/modules/configPreset/import/configPreset-import-utils';
import { CONFIG_PRESET_IMPORT_LOCK_KEY } from '../../../../../src/modules/configPreset/import/configPreset-import-lock';
import { CONFIG_PRESET_FAMILIES } from '../../../../../src/modules/configPreset/configPreset-registry';
import { allFilesForPaths } from '../../../../../src/modules/internal/document/document-domain';
import { deleteFile } from '../../../../../src/database/file-storage';

const UPLOAD_MUTATION = gql`mutation ConfigPresetRunningUpload($file: Upload!) { configPresetImportUpload(file: $file) { id } }`;
const IMPORT_MUTATION = gql`
  mutation ConfigPresetRunningImport($file_id: String!, $selections: [ConfigPresetSelectionInput!]!, $dry_run: Boolean) {
    configPresetImport(file_id: $file_id, selections: $selections, dry_run: $dry_run) { results { key status } }
  }
`;
const SESSION_QUERY = gql`query ConfigPresetRunningSession { configPresetImportSession { status file_id revision selections { type items } total results { key } available_events } }`;
const RUNNING_QUERY = gql`query ConfigPresetRunning { configPresetImportRunning { running { name is_mine started_at processed total } last_finished_at } }`;
const BACK_MUTATION = gql`mutation ConfigPresetRunningBack { configPresetImportSessionBackToSelection { status file_id revision selections { type items } total results { key } } }`;
const CLEAR_MUTATION = gql`mutation ConfigPresetRunningClear($delete_file: Boolean) { configPresetImportSessionClear(delete_file: $delete_file) }`;
const SAVE_MUTATION = gql`
  mutation ConfigPresetRunningSave($file_id: String!, $selections: [ConfigPresetSelectionInput!]!, $revision: Int!) {
    configPresetImportSessionSave(file_id: $file_id, selections: $selections, revision: $revision) { status }
  }
`;
const PREVIEW_QUERY = gql`query ConfigPresetRunningPreview($file_id: ID!) { configPresetImportPreview(file_id: $file_id) { openCTI_version } }`;

const upload = async () => {
  const content = await buildZip(validBundleFiles());
  const result = await queryAsAdminWithSuccess({ query: UPLOAD_MUTATION, variables: { file: createUploadFromBuffer(content, 'bundle.zip') } });
  return result.data?.configPresetImportUpload.id as string;
};
const runImport = (fileId: string, selections: unknown[], dryRun = false) => queryAsAdmin({ query: IMPORT_MUTATION, variables: { file_id: fileId, selections, dry_run: dryRun } });
const readSession = async () => (await queryAsAdminWithSuccess({ query: SESSION_QUERY })).data?.configPresetImportSession;
const readRunning = async () => (await queryAsAdminWithSuccess({ query: RUNNING_QUERY })).data?.configPresetImportRunning;
const zipExists = async (fileId: string) => (await queryAsAdmin({ query: PREVIEW_QUERY, variables: { file_id: fileId } })).errors === undefined;
const messagesImporter = () => CONFIG_PRESET_FAMILIES.find((family) => family.id === 'messages')!.importer!;
const startedAt = '2026-10-27T10:00:00.000Z';
const selections = [{ type: 'messages', items: ['banner'], excluded_items: null }];

// A session stored as applying, as a node that died during the import leaves it
const storeApplying = async (fileId: string, at = startedAt) => {
  await applyConfigPresetImportEvent(testContext, ADMIN_USER, 'SAVE', { file_id: fileId, selections, revision: 1 });
  await applyConfigPresetImportEvent(testContext, ADMIN_USER, 'START', { started_at: at, total: 3, selections });
};
const record = async (overrides: Record<string, unknown> = {}) => ({
  v: 1,
  platform_id: await getConfigPresetPlatformId(testContext),
  user_id: ADMIN_USER.id,
  started_at: startedAt,
  total: 7,
  processed: 4,
  ...overrides,
});

describe('Config preset import: running and interrupted', () => {
  afterEach(async () => {
    vi.restoreAllMocks();
    await queryAsAdmin({ query: CLEAR_MUTATION, variables: { delete_file: true } });
    await getClientBase().del(`config_preset_import_session_${ADMIN_USER.id}`, 'config_preset_import_running', 'config_preset_import_last_finished');
    await setPlatformBootstrapStatus(testContext, ADMIN_USER, 'pending');
    const files = await allFilesForPaths(testContext, ADMIN_USER, ['config_preset/history', 'config_preset/import']);
    for (let i = 0; i < files.length; i += 1) {
      await deleteFile(testContext, ADMIN_USER, files[i].id, { forceDelete: true });
    }
  });

  describe('interrupted session', () => {
    it('reads a session stored as applying as interrupted when no lock is held, and offers back to selection and start over', async () => {
      const fileId = await upload();
      await storeApplying(fileId);
      const session = await readSession();
      expect(session).toMatchObject({ status: 'INTERRUPTED', file_id: fileId });
      expect([...session.available_events].sort()).toEqual(['BACK_TO_SELECTION', 'START_OVER']);
    });

    it('goes back to the selection with the same file and selection, the progress dropped', async () => {
      const fileId = await upload();
      await storeApplying(fileId);
      const back = await queryAsAdminWithSuccess({ query: BACK_MUTATION });
      expect(back.data?.configPresetImportSessionBackToSelection).toMatchObject({ status: 'DRAFT', file_id: fileId, revision: 1, selections: [{ type: 'messages', items: ['banner'] }], total: 0, results: [] });
      expect(await readSession()).toMatchObject({ status: 'DRAFT' });
    });

    it('starts over from an interrupted import: the session and the zip are gone', async () => {
      const fileId = await upload();
      await storeApplying(fileId);
      await queryAsAdminWithSuccess({ query: CLEAR_MUTATION, variables: { delete_file: true } });
      expect(await readSession()).toBeNull();
      expect(await zipExists(fileId)).toBe(false);
    });

    it('refuses an upload, a save and a back to selection when the session is not interrupted', async () => {
      const fileId = await upload();
      const content = await buildZip(validBundleFiles());
      expect((await queryAsAdmin({ query: BACK_MUTATION })).errors?.[0].message).toContain('not available');
      await storeApplying(fileId);
      const refusedUpload = await queryAsAdmin({ query: UPLOAD_MUTATION, variables: { file: createUploadFromBuffer(content, 'other.zip') } });
      expect(refusedUpload.errors?.[0].message).toContain('interrupted');
      const refusedSave = await queryAsAdmin({ query: SAVE_MUTATION, variables: { file_id: fileId, selections: [], revision: 5 } });
      expect(refusedSave.errors?.[0].message).toContain('not available');
      expect(await zipExists(fileId)).toBe(true);
    });

    it('depends on the lock and the record: own record applying, another record or none interrupted or applying', async () => {
      const fileId = await upload();
      await storeApplying(fileId);
      const lock = await lockResource([CONFIG_PRESET_IMPORT_LOCK_KEY]);
      try {
        // Lock held, no record: the window of a node running the lock alone, never interrupted
        expect((await readSession()).status).toEqual('APPLYING');
        await redisSetConfigPresetImportRunning(await record());
        expect((await readSession()).status).toEqual('APPLYING');
        await redisSetConfigPresetImportRunning(await record({ user_id: 'another-user' }));
        expect((await readSession()).status).toEqual('INTERRUPTED');
        await redisSetConfigPresetImportRunning(await record({ started_at: '2026-10-27T11:00:00.000Z' }));
        expect((await readSession()).status).toEqual('INTERRUPTED');
      } finally {
        await lock.unlock();
      }
      // A record left by a dead node is ignored while the lock is not held
      await redisSetConfigPresetImportRunning(await record());
      expect((await readSession()).status).toEqual('INTERRUPTED');
    });

    it('returns the stored status when the lock check cannot answer', async () => {
      const fileId = await upload();
      await storeApplying(fileId);
      vi.spyOn(redisModule, 'isResourceLocked').mockRejectedValue(new Error('redis down'));
      expect((await readSession()).status).toEqual('APPLYING');
      expect((await readRunning()).running).toBeNull();
    });
  });

  describe('running record', () => {
    it('is only updated and deleted by the run that owns it', async () => {
      await redisSetConfigPresetImportRunning(await record({ processed: 0 }));
      expect(await redisUpdateConfigPresetImportRunning('another-user', startedAt, 2)).toBe(false);
      expect(await redisUpdateConfigPresetImportRunning(ADMIN_USER.id, 'another-start', 2)).toBe(false);
      expect(await redisGetConfigPresetImportRunning()).toMatchObject({ processed: 0 });
      // The key prefix reaches the script
      expect(await redisUpdateConfigPresetImportRunning(ADMIN_USER.id, startedAt, 3)).toBe(true);
      expect(await redisGetConfigPresetImportRunning()).toMatchObject({ processed: 3, total: 7, user_id: ADMIN_USER.id });
      expect(await redisDeleteConfigPresetImportRunning('another-user', startedAt)).toBe(false);
      expect(await redisDeleteConfigPresetImportRunning(ADMIN_USER.id, startedAt)).toBe(true);
      expect(await redisGetConfigPresetImportRunning()).toBeNull();
      expect(await redisDeleteConfigPresetImportRunning(ADMIN_USER.id, startedAt)).toBe(false);
    });

    it('reads a record of another platform, of an unknown version or unreadable as no record', async () => {
      const lock = await lockResource([CONFIG_PRESET_IMPORT_LOCK_KEY]);
      try {
        await redisSetConfigPresetImportRunning(await record({ platform_id: 'another-platform' }));
        expect((await readRunning()).running).toBeNull();
        await redisSetConfigPresetImportRunning(await record({ v: 99 }));
        expect((await readRunning()).running).toBeNull();
        await getClientBase().set('config_preset_import_running', '{ not json');
        expect((await readRunning()).running).toBeNull();
      } finally {
        await lock.unlock();
      }
    });
  });

  describe('running import query', () => {
    it('answers no running import without the lock or without the record', async () => {
      expect(await readRunning()).toEqual({ running: null, last_finished_at: null });
      await redisSetConfigPresetImportRunning(await record());
      expect((await readRunning()).running).toBeNull();
      const lock = await lockResource([CONFIG_PRESET_IMPORT_LOCK_KEY]);
      try {
        await getClientBase().del('config_preset_import_running');
        expect((await readRunning()).running).toBeNull();
        await redisSetConfigPresetImportRunning(await record());
        expect((await readRunning()).running).toMatchObject({ name: expect.any(String), is_mine: true, processed: 4, total: 7 });
        await redisSetConfigPresetImportRunning(await record({ user_id: 'deleted-user' }));
        expect((await readRunning()).running).toMatchObject({ name: null, is_mine: false });
      } finally {
        await lock.unlock();
      }
    });

    it('is refused to a user without BYPASS, like back to selection', async () => {
      await queryAsUserIsExpectedForbidden(USER_EDITOR, { query: RUNNING_QUERY });
      await queryAsUserIsExpectedForbidden(USER_EDITOR, { query: BACK_MUTATION });
    });
  });

  describe('a real import', () => {
    it('keeps its record, never reads as interrupted while it runs, tells who runs it, and sets last_finished_at at the end', async () => {
      const fileId = await upload();
      let release: () => void = () => undefined;
      const blocked = new Promise<void>((resolve) => {
        release = resolve;
      });
      const original = messagesImporter().apply;
      vi.spyOn(messagesImporter(), 'apply').mockImplementationOnce(async (...args) => {
        await blocked;
        return original(...args);
      });
      const first = runImport(fileId, [{ type: 'messages' }]);
      try {
        await vi.waitFor(async () => expect((await readSession())?.status).toEqual('APPLYING'));
        const running = (await readRunning()).running;
        expect(running).toMatchObject({ is_mine: true, processed: 0, total: 1 });
        expect(running.name).toEqual(expect.any(String));
        expect(await redisGetConfigPresetImportRunning()).toMatchObject({ user_id: ADMIN_USER.id, total: 1, processed: 0 });
        // The refusal names the administrator who runs the import
        const second = await runImport(fileId, [{ type: 'messages' }]);
        expect(second.errors?.[0].extensions?.data).toMatchObject({ reason: 'import_running', started_by: running.name });
      } finally {
        release();
      }
      expect((await first).errors).toBeUndefined();
      expect(await readSession()).toMatchObject({ status: 'FINISHED' });
      expect(await redisGetConfigPresetImportRunning()).toBeNull();
      expect((await readRunning())).toEqual({ running: null, last_finished_at: expect.anything() });
    });

    it('goes on when its record cannot be updated or deleted, as a failing write never fails the import', async () => {
      const fileId = await upload();
      vi.spyOn(redisModule, 'redisUpdateConfigPresetImportRunning').mockRejectedValue(new Error('redis down'));
      vi.spyOn(redisModule, 'redisDeleteConfigPresetImportRunning').mockRejectedValue(new Error('redis down'));
      expect((await runImport(fileId, [{ type: 'messages' }])).errors).toBeUndefined();
      expect(await readSession()).toMatchObject({ status: 'FINISHED' });
      expect(await redisGetConfigPresetImportLastFinished()).toBeNull();
    });

    it('answers no last_finished_at when it cannot be read', async () => {
      vi.spyOn(redisModule, 'redisGetConfigPresetImportLastFinished').mockRejectedValue(new Error('redis down'));
      expect(await readRunning()).toEqual({ running: null, last_finished_at: null });
    });

    it('writes no record and no last_finished_at for a dry run, and deletes the record without last_finished_at on an error before the first item', async () => {
      const fileId = await upload();
      expect((await runImport(fileId, [{ type: 'messages' }], true)).errors).toBeUndefined();
      expect(await redisGetConfigPresetImportLastFinished()).toBeNull();
      vi.spyOn(userDomain, 'resolveUserByIdFromCache').mockResolvedValueOnce(undefined as never);
      expect((await runImport(fileId, [{ type: 'messages' }])).errors?.[0].message).toContain('no longer exists');
      expect(await redisGetConfigPresetImportRunning()).toBeNull();
      expect(await redisGetConfigPresetImportLastFinished()).toBeNull();
      expect(await readSession()).toMatchObject({ status: 'DRAFT' });
    });
  });
});
