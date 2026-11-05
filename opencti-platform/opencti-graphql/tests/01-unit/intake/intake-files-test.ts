import { describe, expect, it } from 'vitest';
import { fileKeyForm, toUpload, uploadFilesOf, withUploads } from '../../../src/intake/file-values';
import { type FileStorage, rehydrateFiles, removeStagedFiles, stageFiles, STAGING_PATH } from '../../../src/intake/intake-files';
import { UploadFile } from '../../../src/intake/stix-import/types';
import { stripMemberRefMarks } from '../../../src/database/sequencer/sequencer-eligibility';
import { substituteEchoIds } from '../../../src/graphql/chunk-executor';
import { executeChunkOperation } from '../../../src/graphql/chunk-executor';

// The files of the in-process intake: kept in memory by the capture, given to the resolvers as the
// Upload of a multipart request, staged in the object storage when their write is retained.

const memoryStorage = () => {
  const objects = new Map<string, Buffer>();
  const storage: FileStorage = {
    upload: async (key, data) => objects.set(key, data),
    download: async (key) => {
      const data = objects.get(key);
      if (!data) throw new Error(`missing ${key}`);
      return data;
    },
    remove: async (key) => objects.delete(key),
  };
  return { objects, storage };
};

const readUpload = async (promise: Promise<any>) => {
  const { filename, mimetype, createReadStream } = await promise;
  const chunks: Buffer[] = [];
  for await (const chunk of createReadStream()) chunks.push(chunk);
  return { filename, mimetype, data: Buffer.concat(chunks).toString() };
};

const PDF = new UploadFile('report.pdf', Buffer.from('%PDF-1.4 content'), 'application/pdf');

describe('Intake files', () => {
  it('should give the resolvers the Upload a multipart request gives them', async () => {
    const variables = { input: { name: 'Report', files: [PDF] } };
    const uploaded: any = withUploads(variables);
    expect(variables.input.files[0]).toBe(PDF);
    expect(await readUpload(uploaded.input.files[0].promise)).toEqual({ filename: 'report.pdf', mimetype: 'application/pdf', data: '%PDF-1.4 content' });
    // no file: the variables as they are
    const plain = { input: { name: 'Malware' } };
    expect(withUploads(plain)).toBe(plain);
  });

  it('should key a file by its content, never its bytes', () => {
    expect(fileKeyForm({ files: [PDF] })).toEqual({ files: [{ file: { name: 'report.pdf', mime: 'application/pdf', sha256: expect.stringMatching(/^[0-9a-f]{64}$/) } }] });
    expect(fileKeyForm({ files: [new UploadFile('report.pdf', Buffer.from('%PDF-1.4 content'), 'application/pdf')] })).toEqual(fileKeyForm({ files: [PDF] }));
    expect(uploadFilesOf({ a: [PDF, { b: PDF }] })).toEqual([PDF, PDF]);
  });

  it('should keep the variable walkers off a file', () => {
    // a walked file would be rewritten (and its Buffer walked byte by byte)
    const marked = new UploadFile('name||M||', Buffer.from('data'), 'text/plain');
    const echoed = new UploadFile('echo--1', Buffer.from('data'), 'text/plain');
    const variables = { input: { createdBy: 'identity--a||M||', files: [marked, echoed], toId: 'echo--1' } };
    const members = new Set<string>();
    stripMemberRefMarks(variables, members);
    substituteEchoIds(variables, new Map([['echo--1', 'real-id']]));
    expect(variables.input.createdBy).toEqual('identity--a');
    expect(variables.input.toId).toEqual('real-id');
    expect(variables.input.files.map((file) => file.name)).toEqual(['name||M||', 'echo--1']);
  });

  it('should stage the files of a retained write and read them back as they were given', async () => {
    const { objects, storage } = memoryStorage();
    // an operation carries UploadFile, an intent the promise of a FileUpload (what the Upload scalar gives)
    const value = { operation: { input: { files: [PDF] } }, intent: { files: [(toUpload(PDF) as any).promise] }, name: 'kept' };
    const { value: staged, keys } = await stageFiles(value, 'record-1', storage);
    expect(keys).toEqual([`${STAGING_PATH}/record-1/0`, `${STAGING_PATH}/record-1/1`]);
    expect(JSON.parse(JSON.stringify(staged))).toEqual({
      operation: { input: { files: [{ staged_file: { key: `${STAGING_PATH}/record-1/0`, name: 'report.pdf', mime: 'application/pdf' } }] } },
      intent: { files: [{ staged_upload: { key: `${STAGING_PATH}/record-1/1`, filename: 'report.pdf', mimetype: 'application/pdf', encoding: '7bit' } }] },
      name: 'kept',
    });
    const rehydrated: any = await rehydrateFiles(JSON.parse(JSON.stringify(staged)), storage);
    expect(rehydrated.operation.input.files[0]).toBeInstanceOf(UploadFile);
    expect(fileKeyForm(rehydrated.operation)).toEqual(fileKeyForm(value.operation));
    expect(await readUpload(rehydrated.intent.files[0])).toEqual({ filename: 'report.pdf', mimetype: 'application/pdf', data: '%PDF-1.4 content' });
    await removeStagedFiles(keys, storage);
    expect(objects.size).toEqual(0);
  });

  it('should refuse a file over the upload limit of the HTTP edge', async () => {
    const huge = new UploadFile('huge.bin', Buffer.alloc(1), 'application/octet-stream');
    Object.defineProperty(huge.data, 'length', { value: 2 * 1024 * 1024 * 1024 });
    const result = await executeChunkOperation({} as any, { query: 'mutation', variables: { input: { files: [huge] } } });
    expect(result.errors?.[0]?.message).toEqual('File too large for upload');
  });
});
