import { describe, expect, it } from 'vitest';
import { timelineExportErrorMessage } from './useContainerTimelineExport';

const translate = (message: string) => `translated: ${message}`;

describe('Timeline export error message', () => {
  it('asks to narrow an export too large to build at once', () => {
    const tooLarge = {
      res: { errors: [{ message: 'too large', extensions: { code: 'FUNCTIONAL_ERROR', data: { genre: 'BUSINESS', http_status: 400, doc_code: 'TIMELINE_EXPORT_TOO_LARGE' } } }] },
    };
    expect(timelineExportErrorMessage(tooLarge, translate))
      .toEqual('translated: This timeline is too large to export at once: narrow the export with the filters or the time window');
  });

  it('keeps the generic message for any other failure', () => {
    const other = { res: { errors: [{ message: 'forbidden', extensions: { code: 'FORBIDDEN_ACCESS', data: { genre: 'TECHNICAL', http_status: 403 } } }] } };
    expect(timelineExportErrorMessage(other, translate)).toEqual('translated: The timeline export failed');
    expect(timelineExportErrorMessage(new Error('PNG encoding failed'), translate)).toEqual('translated: The timeline export failed');
    expect(timelineExportErrorMessage(null, translate)).toEqual('translated: The timeline export failed');
  });
});
