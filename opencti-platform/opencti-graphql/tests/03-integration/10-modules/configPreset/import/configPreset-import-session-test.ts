import { afterEach, describe, expect, it } from 'vitest';
import gql from 'graphql-tag';
import { buildZip, validBundleFiles } from '../../../../utils/configPresetBundle';
import { createUploadFromBuffer, queryAsAdmin, queryAsAdminWithSuccess, queryAsUserIsExpectedForbidden } from '../../../../utils/testQueryHelper';
import { ADMIN_USER, testContext, USER_EDITOR } from '../../../../utils/testQuery';
import { getClientBase, lockResource, redisSetConfigPresetImportSession } from '../../../../../src/database/redis';
import { CONFIG_PRESET_IMPORT_LOCK_KEY } from '../../../../../src/modules/configPreset/import/configPreset-import-lock';
import { applyConfigPresetImportEvent } from '../../../../../src/modules/configPreset/import/configPreset-import-session-domain';
import { getConfigPresetPlatformId } from '../../../../../src/modules/configPreset/import/configPreset-import-utils';

const SESSION_FIELDS = 'status file_id revision selections { type items excluded_items } started_at total available_events results { key } outcome';

const UPLOAD_MUTATION = gql`mutation ConfigPresetSessionUpload($file: Upload!) { configPresetImportUpload(file: $file) { id } }`;
const SESSION_QUERY = gql(`query ConfigPresetSession { configPresetImportSession { ${SESSION_FIELDS} } }`);
const SAVE_MUTATION = gql(`
  mutation ConfigPresetSessionSave($file_id: String!, $selections: [ConfigPresetSelectionInput!]!, $revision: Int!) {
    configPresetImportSessionSave(file_id: $file_id, selections: $selections, revision: $revision) { ${SESSION_FIELDS} }
  }
`);
const CLEAR_MUTATION = gql`mutation ConfigPresetSessionClear($delete_file: Boolean) { configPresetImportSessionClear(delete_file: $delete_file) }`;
const PREVIEW_QUERY = gql`query ConfigPresetSessionPreview($file_id: ID!) { configPresetImportPreview(file_id: $file_id) { openCTI_version } }`;

const upload = async () => {
  const content = await buildZip(validBundleFiles());
  const result = await queryAsAdminWithSuccess({ query: UPLOAD_MUTATION, variables: { file: createUploadFromBuffer(content, 'bundle.zip') } });
  return result.data?.configPresetImportUpload.id as string;
};
const readSession = async () => (await queryAsAdminWithSuccess({ query: SESSION_QUERY })).data?.configPresetImportSession;
const zipExists = async (fileId: string) => (await queryAsAdmin({ query: PREVIEW_QUERY, variables: { file_id: fileId } })).errors === undefined;
const selections = [{ type: 'messages', items: ['banner'] }, { type: 'branding', excluded_items: ['whitemark'] }];

describe('Config preset import session', () => {
  afterEach(async () => {
    await queryAsAdmin({ query: CLEAR_MUTATION, variables: { delete_file: true } });
    // An applying session is cleared through the store, no event leaves it
    await getClientBase().del(`config_preset_import_session_${ADMIN_USER.id}`);
  });

  it('has no session before any upload', async () => {
    expect(await readSession()).toBeNull();
  });

  it('creates a draft session on upload, and a new upload replaces it with an empty selection', async () => {
    const first = await upload();
    const session = await readSession();
    expect(session).toMatchObject({ status: 'DRAFT', file_id: first, revision: 0, selections: [], started_at: null, total: 0, results: [], outcome: null });
    expect(session.available_events).toEqual(['UPLOAD', 'SAVE', 'START_OVER', 'START']);
    await queryAsAdminWithSuccess({ query: SAVE_MUTATION, variables: { file_id: first, selections, revision: 1 } });
    const second = await upload();
    expect(await readSession()).toMatchObject({ status: 'DRAFT', file_id: second, revision: 0, selections: [] });
  });

  it('saves the selection and ignores a lower revision', async () => {
    const fileId = await upload();
    const saved = await queryAsAdminWithSuccess({ query: SAVE_MUTATION, variables: { file_id: fileId, selections, revision: 2 } });
    expect(saved.data?.configPresetImportSessionSave).toMatchObject({
      revision: 2,
      selections: [{ type: 'messages', items: ['banner'], excluded_items: null }, { type: 'branding', items: null, excluded_items: ['whitemark'] }],
    });
    const stale = await queryAsAdminWithSuccess({ query: SAVE_MUTATION, variables: { file_id: fileId, selections: [], revision: 1 } });
    expect(stale.data?.configPresetImportSessionSave).toMatchObject({ revision: 2, selections: expect.any(Array) });
    expect(stale.data?.configPresetImportSessionSave.selections).toHaveLength(2);
  });

  it('refuses a save without a session and for another file', async () => {
    const withoutSession = await queryAsAdmin({ query: SAVE_MUTATION, variables: { file_id: 'config_preset/import/x/y.zip', selections, revision: 1 } });
    expect(withoutSession.errors?.[0].message).toContain('not available');
    await upload();
    const otherFile = await queryAsAdmin({ query: SAVE_MUTATION, variables: { file_id: 'config_preset/import/x/y.zip', selections, revision: 1 } });
    expect(otherFile.errors?.[0].extensions?.data).toMatchObject({ reason: 'file_missing' });
  });

  it('clears the session, and the pending zip only with delete_file', async () => {
    const kept = await upload();
    await queryAsAdminWithSuccess({ query: CLEAR_MUTATION, variables: { delete_file: false } });
    expect(await readSession()).toBeNull();
    expect(await zipExists(kept)).toBe(true);
    const deleted = await upload();
    await queryAsAdminWithSuccess({ query: CLEAR_MUTATION, variables: { delete_file: true } });
    expect(await readSession()).toBeNull();
    expect(await zipExists(deleted)).toBe(false);
  });

  // A session stored as applying is read as applying while the import lock is held (see the running and interrupted tests)
  it('refuses an upload while applying, before storing anything', async () => {
    const fileId = await upload();
    await applyConfigPresetImportEvent(testContext, ADMIN_USER, 'START', { started_at: new Date().toISOString(), total: 1, selections: [] });
    const lock = await lockResource([CONFIG_PRESET_IMPORT_LOCK_KEY]);
    try {
      expect((await readSession()).status).toEqual('APPLYING');
      const content = await buildZip(validBundleFiles());
      const result = await queryAsAdmin({ query: UPLOAD_MUTATION, variables: { file: createUploadFromBuffer(content, 'other.zip') } });
      expect(result.errors?.[0].message).toContain('An import is in progress');
      expect(await zipExists(fileId)).toBe(true);
      expect((await readSession()).file_id).toEqual(fileId);
    } finally {
      await lock.unlock();
    }
  });

  it('reads a session of another platform, of an unknown version or status, or unreadable, as no session', async () => {
    await upload();
    const key = `config_preset_import_session_${ADMIN_USER.id}`;
    const session = JSON.parse((await getClientBase().get(key))!);
    const platformId = await getConfigPresetPlatformId(testContext);
    expect(session.platform_id).toEqual(platformId);
    await redisSetConfigPresetImportSession(ADMIN_USER.id, { ...session, platform_id: 'another-platform' });
    expect(await readSession()).toBeNull();
    await redisSetConfigPresetImportSession(ADMIN_USER.id, { ...session, v: 99 });
    expect(await readSession()).toBeNull();
    await redisSetConfigPresetImportSession(ADMIN_USER.id, { ...session, status: 'UNKNOWN' });
    expect(await readSession()).toBeNull();
    await getClientBase().set(key, '{ not json');
    expect(await readSession()).toBeNull();
    await redisSetConfigPresetImportSession(ADMIN_USER.id, session);
    expect(await readSession()).toMatchObject({ status: 'DRAFT' });
  });

  it('does not lose the applying state with two concurrent writes of the same session', async () => {
    const fileId = await upload();
    const start = applyConfigPresetImportEvent(testContext, ADMIN_USER, 'START', { started_at: new Date().toISOString(), total: 1, selections: [] });
    const save = applyConfigPresetImportEvent(testContext, ADMIN_USER, 'SAVE', { file_id: fileId, selections: [], revision: 9 });
    await Promise.allSettled([start, save]);
    const lock = await lockResource([CONFIG_PRESET_IMPORT_LOCK_KEY]);
    try {
      expect((await readSession()).status).toEqual('APPLYING');
    } finally {
      await lock.unlock();
    }
  });

  it('keeps the session with a TTL of 30 days', async () => {
    await upload();
    const ttl = await getClientBase().ttl(`config_preset_import_session_${ADMIN_USER.id}`);
    expect(ttl).toBeGreaterThan(29 * 24 * 60 * 60);
    expect(ttl).toBeLessThanOrEqual(30 * 24 * 60 * 60);
  });

  it('refuses the session query and mutations to a user without BYPASS', async () => {
    await queryAsUserIsExpectedForbidden(USER_EDITOR, { query: SESSION_QUERY });
    await queryAsUserIsExpectedForbidden(USER_EDITOR, { query: SAVE_MUTATION, variables: { file_id: 'x', selections: [], revision: 1 } });
    await queryAsUserIsExpectedForbidden(USER_EDITOR, { query: CLEAR_MUTATION, variables: { delete_file: true } });
  });
});
