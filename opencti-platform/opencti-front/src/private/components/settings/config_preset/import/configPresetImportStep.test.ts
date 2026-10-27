import { describe, expect, it } from 'vitest';
import { getConfigPresetErrorReason, getConfigPresetImportStep, getConfigPresetStartedBy } from './configPresetImportStep';
import { toConfigPresetSelection } from './configPresetImportSelection';

const base = { status: null, hasChosenImport: false, isFileMissing: false, isApplying: false };

describe('getConfigPresetImportStep', () => {
  it('shows the welcome choices without session, then the upload once the import is chosen', () => {
    expect(getConfigPresetImportStep(base)).toEqual('welcome');
    expect(getConfigPresetImportStep({ ...base, hasChosenImport: true })).toEqual('upload');
    expect(getConfigPresetImportStep({ ...base, status: undefined })).toEqual('welcome');
  });

  it('picks the step of the session status', () => {
    expect(getConfigPresetImportStep({ ...base, status: 'DRAFT' })).toEqual('preview');
    expect(getConfigPresetImportStep({ ...base, status: 'APPLYING' })).toEqual('progress');
    expect(getConfigPresetImportStep({ ...base, status: 'FINISHED' })).toEqual('result');
    expect(getConfigPresetImportStep({ ...base, status: 'INTERRUPTED' })).toEqual('interrupted');
  });

  it('shows the progress while the own import runs, whatever the status', () => {
    expect(getConfigPresetImportStep({ ...base, status: 'DRAFT', isApplying: true })).toEqual('progress');
    expect(getConfigPresetImportStep({ ...base, isApplying: true })).toEqual('progress');
  });

  it('goes back to the upload when the file is missing, except while applying', () => {
    expect(getConfigPresetImportStep({ ...base, status: 'DRAFT', isFileMissing: true })).toEqual('upload');
    expect(getConfigPresetImportStep({ ...base, status: 'FINISHED', isFileMissing: true })).toEqual('upload');
    expect(getConfigPresetImportStep({ ...base, status: 'APPLYING', isFileMissing: true })).toEqual('progress');
  });
});

describe('getConfigPresetErrorReason', () => {
  it('reads the reason of the first error, never the message', () => {
    expect(getConfigPresetErrorReason({ res: { errors: [{ message: 'x', extensions: { code: 'FUNCTIONAL_ERROR', data: { reason: 'file_missing' } } }] } })).toEqual('file_missing');
    expect(getConfigPresetErrorReason({ res: { errors: [{ message: 'file_missing' }] } })).toBeUndefined();
    expect(getConfigPresetErrorReason(new Error('network'))).toBeUndefined();
  });
});

describe('getConfigPresetStartedBy', () => {
  it('reads the name of the administrator from the data of the refusal', () => {
    expect(getConfigPresetStartedBy({ res: { errors: [{ extensions: { data: { reason: 'import_running', started_by: 'Jane' } } }] } })).toEqual('Jane');
    expect(getConfigPresetStartedBy({ res: { errors: [{ extensions: { data: { reason: 'import_running' } } }] } })).toBeUndefined();
    expect(getConfigPresetStartedBy(new Error('x'))).toBeUndefined();
  });
});

describe('toConfigPresetSelection', () => {
  it('maps the saved selection of the session to the selection of the list', () => {
    expect(toConfigPresetSelection([
      { type: 'messages', items: ['banner'], excluded_items: null },
      { type: 'branding', items: null, excluded_items: ['whitemark'] },
      { type: 'platform', items: null, excluded_items: null },
    ])).toEqual({
      messages: { mode: 'some', ids: ['banner'] },
      branding: { mode: 'all', ids: ['whitemark'] },
      platform: { mode: 'all', ids: [] },
    });
  });
});
