import { head } from 'ramda';
import { deleteFile, downloadFile, filesListing, loadFile } from '../../../src/database/minio';
import { listenServer, stopServer } from '../../../src/httpServer';
import { execPython3 } from '../../../src/python/pythonBridge';
import { ADMIN_USER, API_TOKEN, API_URI, PYTHON_PATH } from '../../utils/testQuery';
import { elLoadByIds } from '../../../src/database/elasticSearch';

const streamConverter = (stream) => {
  return new Promise((resolve) => {
    let data = '';
    stream.on('data', (chunk) => {
      data += chunk.toString();
    });
    stream.on('end', () => resolve(data));
  });
};

describe('Minio file listing', () => {
  let malwareId;
  let exportFileName;
  let exportFileId;
  let importFileId;
  let importOpts;
  it('should resolve the malware', async () => {
    const malware = await elLoadByIds(ADMIN_USER, 'malware--faa5b705-cf44-4e50-8472-29e5fec43c3c');
    malwareId = malware.internal_id;
    exportFileName = '(ExportFileStix)_Malware-Paradise Ransomware_all.json';
    exportFileId = `export/Malware/${malwareId}/${exportFileName}`;
    importFileId = `import/global/${exportFileName}`;
    importOpts = [API_URI, API_TOKEN, malwareId, exportFileName];
  });
  it('should file upload succeed', async () => {
    const httpServer = await listenServer();
    // local exporter create an export and also upload the file as an import
    const execution = await execPython3(PYTHON_PATH, 'local_exporter.py', importOpts);
    expect(execution).not.toBeNull();
    expect(execution.status).toEqual('success');
    await stopServer(httpServer);
  });
  it('should file listing', async () => {
    const entity = { id: malwareId };
    let list = await filesListing(ADMIN_USER, 25, `export/Malware/${entity.id}/`);
    expect(list).not.toBeNull();
    expect(list.edges.length).toEqual(1);
    let file = head(list.edges).node;
    expect(file.id).toEqual(exportFileId);
    expect(file.name).toEqual(exportFileName);
    expect(file.size).toEqual(10513);
    expect(file.metaData).not.toBeNull();
    expect(file.metaData.encoding).toEqual('7bit');
    expect(file.metaData.filename).toEqual(exportFileName.replace(/\s/g, '%20'));
    expect(file.metaData.mimetype).toEqual('text/plain');
    list = await filesListing(ADMIN_USER, 25, 'import/global/');
    expect(list).not.toBeNull();
    expect(list.edges.length).toEqual(1);
    file = head(list.edges).node;
    expect(file.id).toEqual(importFileId);
    expect(file.size).toEqual(10513);
    expect(file.name).toEqual(exportFileName);
  });
  it('should file download', async () => {
    const fileStream = await downloadFile(exportFileId);
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
    const file = await loadFile(ADMIN_USER, exportFileId);
    expect(file).not.toBeNull();
    expect(file.id).toEqual(exportFileId);
    expect(file.name).toEqual(exportFileName);
    expect(file.size).toEqual(10513);
  });
  it('should delete file', async () => {
    let deleted = await deleteFile(ADMIN_USER, exportFileId);
    expect(deleted).toBeTruthy();
    deleted = await deleteFile(ADMIN_USER, importFileId);
    expect(deleted).toBeTruthy();
  });
});
