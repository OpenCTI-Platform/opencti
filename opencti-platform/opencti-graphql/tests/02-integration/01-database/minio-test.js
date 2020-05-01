import { head } from 'ramda';
import { internalLoadEntityByStixId } from '../../../src/database/grakn';
import {
  deleteFile,
  downloadFile,
  extractName,
  filesListing,
  generateFileExportName,
  getMinIOVersion,
  loadFile,
} from '../../../src/database/minio';
import { listenServer, stopServer } from '../../../src/httpServer';
import { execPython3 } from '../../../src/python/pythonBridge';
import { API_TOKEN, API_URI, PYTHON_PATH } from '../../utils/testQuery';

const streamConverter = (stream) => {
  return new Promise((resolve) => {
    let data = '';
    stream.on('data', (chunk) => {
      data += chunk.toString();
    });
    stream.on('end', () => resolve(data));
  });
};

describe('Minio basic and utils', () => {
  it('should minio in correct version', async () => {
    const minioVersion = await getMinIOVersion();
    expect(minioVersion).toEqual(expect.stringContaining('RELEASE.20'));
  });
  it('should simple name correctly generated', async () => {
    let fileName = extractName(null, null, 'test-filename');
    expect(fileName).toEqual('global/test-filename');
    fileName = extractName('Malware', null, 'test-filename');
    expect(fileName).toEqual('malware/lists/test-filename');
    fileName = generateFileExportName('application/json', { name: 'ExportFileStix' });
    expect(fileName).toEqual(expect.stringContaining('_(ExportFileStix)_null.json'));
    fileName = generateFileExportName('application/json', { name: 'ExportFileStix' }, null, 'full');
    expect(fileName).toEqual(expect.stringContaining('_(ExportFileStix)_full.json'));
  });
  it('should entity export name correctly generated', async () => {
    const type = 'malware';
    const exportType = 'all';
    const connector = { name: 'ExportFileStix' };
    const maxMarking = { definition: 'TLP:RED' };
    const entity = await internalLoadEntityByStixId('malware--faa5b705-cf44-4e50-8472-29e5fec43c3c');
    const fileExportName = generateFileExportName('application/json', connector, entity, type, exportType, maxMarking);
    const expectedName = '_TLP:RED_(ExportFileStix)_malware-Paradise Ransomware_all.json';
    expect(fileExportName).toEqual(expect.stringContaining(expectedName));
  });
  it('should list export name correctly generated', async () => {
    const type = 'attack-pattern';
    const exportType = 'all';
    const connector = { name: 'ExportFileStix' };
    const maxMarking = { definition: 'TLP:RED' };
    const entity = null;
    const fileExportName = generateFileExportName('application/json', connector, entity, type, exportType, maxMarking);
    const expectedName = '_TLP:RED_(ExportFileStix)_attack-pattern.json';
    expect(fileExportName).toEqual(expect.stringContaining(expectedName));
  });
});

describe('Minio file listing', () => {
  const malwareId = 'ab78a62f-4928-4d5a-8740-03f0af9c4330';
  const exportFileName = '(ExportFileStix)_malware-Paradise Ransomware_all.json';
  const exportFileId = `export/malware/${malwareId}/${exportFileName}`;
  const importFileId = `import/global/${exportFileName}`;
  const importOpts = [API_URI, API_TOKEN, malwareId, exportFileName];
  it('Should file upload succeed', async () => {
    const httpServer = await listenServer();
    // local exporter create an export and also upload the file as an import
    const execution = await execPython3(PYTHON_PATH, 'local_exporter.py', importOpts);
    expect(execution).not.toBeNull();
    expect(execution.status).toEqual('success');
    await stopServer(httpServer);
  });
  it('should file listing', async () => {
    const entity = { id: malwareId };
    let list = await filesListing(25, 'export', 'Malware', entity);
    expect(list).not.toBeNull();
    expect(list.edges.length).toEqual(1);
    let file = head(list.edges).node;
    expect(file.id).toEqual(exportFileId);
    expect(file.name).toEqual(exportFileName);
    expect(file.size).toEqual(18481);
    expect(file.metaData).not.toBeNull();
    expect(file.metaData['content-type']).toEqual('application/octet-stream');
    expect(file.metaData.category).toEqual('export');
    expect(file.metaData.encoding).toEqual('7bit');
    expect(file.metaData.filename).toEqual(exportFileName.replace(/\s/g, '%20'));
    expect(file.metaData.mimetype).toEqual('text/plain');
    list = await filesListing(25, 'import');
    expect(list).not.toBeNull();
    expect(list.edges.length).toEqual(1);
    file = head(list.edges).node;
    expect(file.id).toEqual(importFileId);
    expect(file.size).toEqual(18481);
    expect(file.name).toEqual(exportFileName);
  });
  it('should file download', async () => {
    const fileStream = await downloadFile(exportFileId);
    expect(fileStream).not.toBeNull();
    const data = await streamConverter(fileStream);
    expect(data).not.toBeNull();
    const jsonData = JSON.parse(data);
    expect(jsonData).not.toBeNull();
    expect(jsonData.objects.length).toEqual(16);
    const user = head(jsonData.objects);
    expect(user.name).toEqual('admin');
    expect(user.x_opencti_id).toEqual('88ec0c6a-13ce-5e39-b486-354fe4a7084f');
  });
  it('should load file', async () => {
    const file = await loadFile(exportFileId);
    expect(file).not.toBeNull();
    expect(file.id).toEqual(exportFileId);
    expect(file.name).toEqual(exportFileName);
    expect(file.size).toEqual(18481);
  });
  it('should delete file', async () => {
    let deleted = await deleteFile({ user_email: 'test@opencti.io' }, exportFileId);
    expect(deleted).toBeTruthy();
    deleted = await deleteFile({ user_email: 'test@opencti.io' }, importFileId);
    expect(deleted).toBeTruthy();
  });
});
