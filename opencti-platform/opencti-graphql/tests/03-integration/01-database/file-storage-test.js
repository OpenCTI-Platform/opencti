import { beforeEach, expect, it, describe, vi } from 'vitest';
import { head } from 'ramda';
import { downloadFile, storageInit } from '../../../src/database/raw-file-storage';
import {
  deleteFile,
  getFileName,
  guessMimeType,
  isFileObjectExcluded,
  loadedFilesListing,
  loadFile,
  specialTypesExtensions,
  storeFileConverter,
  streamConverter,
} from '../../../src/database/file-storage';
import { execChildPython } from '../../../src/python/pythonBridge';
import { ADMIN_USER, testContext, ADMIN_API_TOKEN, API_URI, PYTHON_PATH } from '../../utils/testQuery';
import { elLoadById } from '../../../src/database/engine';
import { allFilesForPaths, paginatedForPathWithEnrichment } from '../../../src/modules/internal/document/document-domain';
import { utcDate } from '../../../src/utils/format';
import { MARKING_TLP_AMBER_STRICT } from '../../../src/schema/identifier';
import { storeLoadById } from '../../../src/database/middleware-loader';
import { ENTITY_TYPE_MARKING_DEFINITION } from '../../../src/schema/stixMetaObject';

const exportFileName = '(ExportFileStix)_Malware-Paradise Ransomware_all.json';
const exportFileId = (malware) => `export/Malware/${malware.id}/${exportFileName.toLowerCase()}`;
const importFileId = `import/global/${exportFileName.toLowerCase()}`;
const FILE_SIZE = 10700;

describe('File storage file listing', () => {
  it('should initializeFilStorage initializes without error', async () => {
    await expect(storageInit()).resolves.not.toThrow();
  });

  it('should file upload succeed', async () => {
    const malware = await elLoadById(testContext, ADMIN_USER, 'malware--faa5b705-cf44-4e50-8472-29e5fec43c3c');
    const importOpts = [API_URI, ADMIN_API_TOKEN, malware.id, 'Malware', exportFileName, [MARKING_TLP_AMBER_STRICT]];
    // local exporter create an export and also upload the file as an import
    const execution = await execChildPython(testContext, ADMIN_USER, PYTHON_PATH, 'local_exporter.py', importOpts);
    expect(execution).not.toBeNull();
    expect(execution.status).toEqual('success');
  });
  it('should paginate file listing', async () => {
    const malware = await elLoadById(testContext, ADMIN_USER, 'malware--faa5b705-cf44-4e50-8472-29e5fec43c3c');
    let list = await paginatedForPathWithEnrichment(testContext, ADMIN_USER, `export/Malware/${malware.id}`, malware.id, { first: 25 });
    expect(list).not.toBeNull();
    expect(list.edges.length).toEqual(1);
    let file = head(list.edges).node;
    expect(file.id).toEqual(exportFileId(malware));
    expect(file.name).toEqual(exportFileName);
    expect(file.size).toEqual(FILE_SIZE);
    expect(file.metaData).not.toBeNull();
    const tlpAmberMarking = await storeLoadById(testContext, ADMIN_USER, MARKING_TLP_AMBER_STRICT, ENTITY_TYPE_MARKING_DEFINITION);
    expect(file.metaData.file_markings[0]).toEqual(tlpAmberMarking.internal_id);
    expect(file.metaData.encoding).toEqual('7bit');
    expect(file.metaData.filename).toEqual(exportFileName.replace(/\s/g, '%20'));
    expect(file.metaData.mimetype).toEqual('application/json');
    list = await paginatedForPathWithEnrichment(testContext, ADMIN_USER, 'import/global', undefined, { first: 25 });
    expect(list).not.toBeNull();
    expect(list.edges.length).toEqual(1);
    file = head(list.edges).node;
    expect(file.id).toEqual(importFileId);
    expect(file.size).toEqual(FILE_SIZE);
    expect(file.name).toEqual(exportFileName);
  });
  it('should all file listing', async () => {
    const malware = await elLoadById(testContext, ADMIN_USER, 'malware--faa5b705-cf44-4e50-8472-29e5fec43c3c');
    const paths = [`export/Malware/${malware.id}`];
    // Global search
    let files = await allFilesForPaths(testContext, ADMIN_USER, paths);
    expect(files.length).toEqual(1);
    // Mime type filtering
    files = await allFilesForPaths(testContext, ADMIN_USER, paths, { prefixMimeTypes: ['application'] });
    expect(files.length).toEqual(1);
    files = await allFilesForPaths(testContext, ADMIN_USER, paths, { prefixMimeTypes: ['image'] });
    expect(files.length).toEqual(0);
    // Entity id filtering
    files = await allFilesForPaths(testContext, ADMIN_USER, ['export/Malware'], { entity_id: malware.id });
    expect(files.length).toEqual(1);
    files = await allFilesForPaths(testContext, ADMIN_USER, ['export/Malware'], { entity_id: 'unknow_id' });
    expect(files.length).toEqual(0);
    // maxFileSize filtering
    files = await allFilesForPaths(testContext, ADMIN_USER, ['export/Malware'], { maxFileSize: 11576 });
    expect(files.length).toEqual(1);
    files = await allFilesForPaths(testContext, ADMIN_USER, ['export/Malware'], { maxFileSize: 1692 });
    expect(files.length).toEqual(0);
    // modifiedSince filtering
    const oneMinuteAgo = utcDate().subtract(5, 'minutes');
    files = await allFilesForPaths(testContext, ADMIN_USER, paths, { modifiedSince: oneMinuteAgo.toISOString() });
    expect(files.length).toEqual(1);
    files = await allFilesForPaths(testContext, ADMIN_USER, paths, { modifiedSince: utcDate().toISOString() });
    expect(files.length).toEqual(0);
    // excludedPaths filtering
    files = await allFilesForPaths(testContext, ADMIN_USER, ['export']);
    expect(files.length).toEqual(1);
    files = await allFilesForPaths(testContext, ADMIN_USER, ['export'], { excludedPaths: ['export/Malware'] });
    expect(files.length).toEqual(0);
  });
  it('should file download', async () => {
    const malware = await elLoadById(testContext, ADMIN_USER, 'malware--faa5b705-cf44-4e50-8472-29e5fec43c3c');
    const fileStream = await downloadFile(exportFileId(malware));
    expect(fileStream).not.toBeNull();
    const data = await streamConverter(fileStream);
    expect(data).not.toBeNull();
    const jsonData = JSON.parse(data);
    expect(jsonData).not.toBeNull();
    expect(jsonData.objects.length).toEqual(9);
    const user = head(jsonData.objects);
    expect(user.name).toEqual('Paradise Ransomware');
  });
  it('should non existing download return null', async () => {
    const fileStream = await downloadFile('ThisDoesNotExists');
    expect(fileStream).toBeNull();
  });
  it('should load file', async () => {
    const malware = await elLoadById(testContext, ADMIN_USER, 'malware--faa5b705-cf44-4e50-8472-29e5fec43c3c');
    const file = await loadFile(testContext, ADMIN_USER, exportFileId(malware));
    expect(file).not.toBeNull();
    expect(file.id).toEqual(exportFileId(malware));
    expect(file.name).toEqual(exportFileName);
    expect(file.size).toEqual(FILE_SIZE);
    expect(file.metaData).toBeDefined();
    expect(file.metaData.mimetype).toBe('application/json');
  });
  it('should not load file if user does not have capability', async () => {
    const malware = await elLoadById(testContext, ADMIN_USER, 'malware--faa5b705-cf44-4e50-8472-29e5fec43c3c');
    const authUserNoCapa = {
      id: '1deb38a8-d2c8-4b5f-9c82-e9b6e5220603',
      internal_id: '1deb38a8-d2c8-4b5f-9c82-e9b6e5220603',
      user_email: 'user-no-capa@opencti.io',
      allowed_marking: [],
      roles: [{ internal_id: '08f558bc-b93d-40dc-8e86-f70309d9e1a6', id: '08f558bc-b93d-40dc-8e86-f70309d9e1a6', name: 'No capa' }],
      groups: [],
      capabilities: [],
      organizations: [],
    };
    await expect(async () => {
      await loadFile(testContext, authUserNoCapa, exportFileId(malware));
    }).rejects.toThrowError('File not found or restricted');
    // no access to global file
    await expect(async () => {
      await loadFile(testContext, authUserNoCapa, importFileId);
    }).rejects.toThrowError('File not found or restricted');
    // other tests, fake paths, just to be sure we check the right capa before loading the files
    await expect(async () => {
      await loadFile(testContext, authUserNoCapa, 'import/Report/fc21ca91-7cbd-4814-89cd-fe0c9489b91a/report.pdf');
    }).rejects.toThrowError('File not found or restricted');
    await expect(async () => {
      await loadFile(testContext, authUserNoCapa, 'fromTemplate/Report/fc21ca91-7cbd-4814-89cd-fe0c9489b91a/reporttemplate.pdf');
    }).rejects.toThrowError('File not found or restricted');
  });
  it('should delete file', async () => {
    const malware = await elLoadById(testContext, ADMIN_USER, 'malware--faa5b705-cf44-4e50-8472-29e5fec43c3c');
    let deleted = await deleteFile(testContext, ADMIN_USER, exportFileId(malware));
    expect(deleted).toBeTruthy();
    deleted = await deleteFile(testContext, ADMIN_USER, importFileId);
    expect(deleted).toBeTruthy();
  });
});

describe('File storage utils', () => {
  it('should guess mimetype correctly', async () => {
    expect(guessMimeType('pdf_report')).toBe('application/pdf');
    expect(guessMimeType('path/1/file.yar')).toBe('text/yara+plain');
    expect(guessMimeType('path/to/iamajsonfile.json')).toBe('application/json');
    expect(guessMimeType('path/to/iamapdf.pdf')).toBe('application/pdf');
    expect(guessMimeType('path/to/i Have space and 💖.txt')).toBe('text/plain');
    expect(guessMimeType('unknown')).toBe('application/octet-stream');
    expect(guessMimeType('export/Malware/b4bebef0-7f1b-4212-b09d-f376adb3181a/(ExportFileStix)_Malware-Paradise Ransomware_all.json')).toBe('application/json');
  });
  it('should find filename correctly', async () => {
    expect(getFileName('path/to/iamajsonfile.json')).toBe('iamajsonfile.json');
    expect(getFileName('path/to/iamapdf.pdf')).toBe('iamapdf.pdf');
    expect(getFileName('unknown')).toBe('unknown');
    expect(getFileName('path/to/i Have spàcé and 💖.txt')).toBe('i Have spàcé and 💖.txt');
  });

  it('should exclude .DS_Store files regardless of case', async () => {
    expect(isFileObjectExcluded('path/to/.DS_Store')).toBe(true);
    expect(isFileObjectExcluded('import/global/.DS_Store')).toBe(true);
    expect(isFileObjectExcluded('path/.ds_store')).toBe(true);
  });

  it('should not exclude normal files', async () => {
    expect(isFileObjectExcluded('path/document.pdf')).toBe(false);
    expect(isFileObjectExcluded('import/file.json')).toBe(false);
    expect(isFileObjectExcluded('data.csv')).toBe(false);
    expect(isFileObjectExcluded('path/my_DS_Store_backup.txt')).toBe(false);
  });

  it('should convert loaded file to x_opencti_file format', async () => {
    const file = {
      id: 'file-id-123',
      name: 'test.pdf',
      size: 1024,
      information: '',
      lastModified: new Date(),
      lastModifiedSinceMin: 0,
      metaData: {
        version: '1.0',
        mimetype: 'application/pdf',
        file_markings: ['marking-1', 'marking-2'],
      },
      uploadStatus: 'complete',
    };

    const result = storeFileConverter(ADMIN_USER, file);

    expect(result).toEqual({
      id: 'file-id-123',
      name: 'test.pdf',
      version: '1.0',
      mime_type: 'application/pdf',
      file_markings: ['marking-1', 'marking-2'],
    });
  });

  it('should convert loaded file with missing optional metadata', async () => {
    const file = {
      id: 'file-id-empty',
      name: 'empty.dat',
      size: 0,
      information: '',
      lastModified: new Date(),
      lastModifiedSinceMin: 0,
      metaData: {},
      uploadStatus: 'complete',
    };

    const result = storeFileConverter(ADMIN_USER, file);

    expect(result).toEqual({
      id: 'file-id-empty',
      name: 'empty.dat',
      version: undefined,
      mime_type: undefined,
      file_markings: [],
    });
  });

  it('should expose special extension mapping constants', async () => {
    expect(specialTypesExtensions['application/vnd.oasis.stix+json']).toBe('json');
    expect(specialTypesExtensions['application/vnd.mitre.navigator+json']).toBe('json');
  });
});

describe('File storage guard rails', () => {
  const noCapabilityUser = {
    id: '1deb38a8-d2c8-4b5f-9c82-e9b6e5220603',
    internal_id: '1deb38a8-d2c8-4b5f-9c82-e9b6e5220603',
    user_email: 'user-no-capa@opencti.io',
    allowed_marking: [],
    roles: [{ internal_id: '08f558bc-b93d-40dc-8e86-f70309d9e1a6', id: '08f558bc-b93d-40dc-8e86-f70309d9e1a6', name: 'No capa' }],
    groups: [],
    capabilities: [],
    organizations: [],
  };

  beforeEach(() => {
    vi.restoreAllMocks();
  });

  it('should throw when file path is empty', async () => {
    await expect(async () => {
      await loadFile(testContext, ADMIN_USER, '');
    }).rejects.toThrowError('File path not specified');
  });

  it('should return undefined for restricted support path when dontThrow is true', async () => {
    const result = await loadFile(testContext, noCapabilityUser, 'support/some-package/file.zip', { dontThrow: true });
    expect(result).toBeUndefined();
  });

  it('should reject embedded file without knowledge capability', async () => {
    await expect(async () => {
      await loadFile(testContext, noCapabilityUser, 'embedded/Note/n1/image.png');
    }).rejects.toThrowError('File not found or restricted');
  });

  it('should reject import/global file without capability', async () => {
    await expect(async () => {
      await loadFile(testContext, noCapabilityUser, 'import/global/test.csv');
    }).rejects.toThrowError('File not found or restricted');
  });

  it('should reject deletion of non-draft file in draft context', async () => {
    const contextInDraft = { ...testContext, draft_context: 'draft-1' };
    await expect(async () => {
      await deleteFile(contextInDraft, ADMIN_USER, 'import/global/test.csv');
    }).rejects.toThrowError('Cannot delete non draft imports in draft');
  });

  it('should reject listing directory starting with slash', async () => {
    await expect(async () => {
      await loadedFilesListing(testContext, ADMIN_USER, '/import/global/');
    }).rejects.toThrowError('File listing directory must not start with a /');
  });

  it('should reject listing directory not ending with slash', async () => {
    await expect(async () => {
      await loadedFilesListing(testContext, ADMIN_USER, 'import/global');
    }).rejects.toThrowError('File listing directory must end with a /');
  });
});
