import { describe, expect, it } from 'vitest';
import type { Readable } from 'stream';
import { streamToString } from '../../../src/database/raw-file-storage';
import { checkConfigurationImport } from '../../../src/modules/workspace/workspace-domain';
import { createUploadFromTestDataFile } from '../../utils/testQueryHelper';

describe('workspace', () => {
  const cases = [
    ['20233010_octi_dashboard_Custom Dash_invalid_5.11.0_version.json', 'Invalid version of the platform. Please upgrade your OpenCTI. Minimal version required: 5.12.16'],
    ['20233010_octi_dashboard_Custom Dash_invalid_5.10.5_version.json', 'Invalid version of the platform. Please upgrade your OpenCTI. Minimal version required: 5.12.16'],
    ['20233010_octi_dashboard_Custom Dash_invalid_4.0.4_version.json', 'Invalid version of the platform. Please upgrade your OpenCTI. Minimal version required: 5.12.16'],
  ];
  it.each(cases)('should verify import version compatibility, given invalid version (%s for error %s)', async (filePath, expectedErrorMessage) => {
    const upload = await createUploadFromTestDataFile(filePath, 'invalid-version.json', 'application/json', 'utf8');
    const readStream = upload.file?.createReadStream();
    expect(readStream).toBeDefined();
    const fileContent = await streamToString(readStream as Readable);
    const parsedData = JSON.parse(fileContent.toString());
    const check = () => {
      checkConfigurationImport('dashboard', parsedData);
    };
    expect(check).toThrowError(expectedErrorMessage);
  });

  it('should verify import version compatibility, given invalid type', async () => {
    const upload = await createUploadFromTestDataFile('20233010_octi_dashboard_Custom Dash_invalid_type.json', 'invalid-version.json', 'application/json', 'utf8');
    const readStream = upload.file?.createReadStream();
    expect(readStream).toBeDefined();
    const fileContent = await streamToString(readStream as Readable);
    const parsedData = JSON.parse(fileContent.toString());

    expect(() => checkConfigurationImport('dashboard', parsedData)).toThrowError('Invalid type. Please import OpenCTI dashboard-type only');
  });

  it('should verify import version compatibility, given valid import', async () => {
    const upload = await createUploadFromTestDataFile('20233010_octi_dashboard_Custom Dash_valid.json', 'invalid-version.json', 'application/json', 'utf8');
    const readStream = upload.file?.createReadStream();
    expect(readStream).toBeDefined();
    const fileContent = await streamToString(readStream as Readable);
    const parsedData = JSON.parse(fileContent.toString());

    expect(() => checkConfigurationImport('dashboard', parsedData),).not.toThrowError();
  });
});
