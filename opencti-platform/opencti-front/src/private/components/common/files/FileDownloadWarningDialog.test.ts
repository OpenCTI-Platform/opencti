import { describe, expect, it } from 'vitest';
import { isPotentiallyMaliciousFile } from './FileDownloadWarningDialog';

describe('isPotentiallyMaliciousFile', () => {
  it('flags every file of an Artifact', () => {
    expect(isPotentiallyMaliciousFile('import/Artifact/abc/shot.png', true)).toBe(true);
  });

  it('flags binaries whatever their entity, ignoring the case of the extension', () => {
    expect(isPotentiallyMaliciousFile('import/Report/abc/setup.exe')).toBe(true);
    expect(isPotentiallyMaliciousFile('import/Report/abc/run.PIF')).toBe(true);
    expect(isPotentiallyMaliciousFile('import/Report/abc/lib.dll')).toBe(true);
  });

  it('does not flag other files', () => {
    expect(isPotentiallyMaliciousFile('import/Report/abc/report.pdf')).toBe(false);
    expect(isPotentiallyMaliciousFile('import/Report/abc/shot.png', false)).toBe(false);
  });
});
