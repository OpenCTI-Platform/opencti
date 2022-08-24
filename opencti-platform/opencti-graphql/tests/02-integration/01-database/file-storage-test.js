import { head } from 'ramda';
import { deleteFile, downloadFile, filesListing, loadFile } from '../../../src/database/file-storage';
import { execPython3 } from '../../../src/python/pythonBridge';
import { ADMIN_USER, API_TOKEN, API_URI, PYTHON_PATH } from '../../utils/testQuery';
import { elLoadById } from '../../../src/database/engine';
import { startModules, shutdownModules } from '../../../src/modules';

const streamConverter = (stream) => {
  return new Promise((resolve) => {
    let data = '';
    stream.on('data', (chunk) => {
      data += chunk.toString();
    });
    stream.on('end', () => resolve(data));
  });
};

const exportFileName = '(ExportFileStix)_Malware-Paradise Ransomware_all.json';
const exportFileId = (malware) => `export/Malware/${malware.id}/${exportFileName}`;
const importFileId = `import/global/${exportFileName}`;

describe('File storage file listing', () => {
  it('should file upload succeed', async () => {
    await startModules();
    const malware = await elLoadById(ADMIN_USER, 'malware--faa5b705-cf44-4e50-8472-29e5fec43c3c');
    const importOpts = [API_URI, API_TOKEN, malware.id, exportFileName];
    // local exporter create an export and also upload the file as an import
    const execution = await execPython3(PYTHON_PATH, 'local_exporter.py', importOpts);
    expect(execution).not.toBeNull();
    expect(execution.status).toEqual('success');
    await shutdownModules();
  });
  it('should file listing', async () => {
    const malware = await elLoadById(ADMIN_USER, 'malware--faa5b705-cf44-4e50-8472-29e5fec43c3c');
    let list = await filesListing(ADMIN_USER, 25, `export/Malware/${malware.id}/`);
    expect(list).not.toBeNull();
    expect(list.edges.length).toEqual(1);
    let file = head(list.edges).node;
    expect(file.id).toEqual(exportFileId(malware));
    expect(file.name).toEqual(exportFileName);
    expect(file.size).toEqual(10566);
    expect(file.metaData).not.toBeNull();
    expect(file.metaData.encoding).toEqual('7bit');
    expect(file.metaData.filename).toEqual(exportFileName.replace(/\s/g, '%20'));
    expect(file.metaData.mimetype).toEqual('application/json');
    list = await filesListing(ADMIN_USER, 25, 'import/global/');
    expect(list).not.toBeNull();
    expect(list.edges.length).toEqual(1);
    file = head(list.edges).node;
    expect(file.id).toEqual(importFileId);
    expect(file.size).toEqual(10566);
    expect(file.name).toEqual(exportFileName);
  });
  it('should file download', async () => {
    const malware = await elLoadById(ADMIN_USER, 'malware--faa5b705-cf44-4e50-8472-29e5fec43c3c');
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
  it('should load file', async () => {
    const malware = await elLoadById(ADMIN_USER, 'malware--faa5b705-cf44-4e50-8472-29e5fec43c3c');
    const file = await loadFile(ADMIN_USER, exportFileId(malware));
    expect(file).not.toBeNull();
    expect(file.id).toEqual(exportFileId(malware));
    expect(file.name).toEqual(exportFileName);
    expect(file.size).toEqual(10566);
  });
  it('should delete file', async () => {
    const malware = await elLoadById(ADMIN_USER, 'malware--faa5b705-cf44-4e50-8472-29e5fec43c3c');
    let deleted = await deleteFile(ADMIN_USER, exportFileId(malware));
    expect(deleted).toBeTruthy();
    deleted = await deleteFile(ADMIN_USER, importFileId);
    expect(deleted).toBeTruthy();
  });
});
