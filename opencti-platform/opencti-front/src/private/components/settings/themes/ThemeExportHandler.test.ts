import { beforeEach, describe, expect, it, vi } from 'vitest';

const { fetchQuery, fileDownload } = vi.hoisted(() => ({ fetchQuery: vi.fn(), fileDownload: vi.fn() }));
vi.mock('../../../../relay/environment', () => ({ fetchQuery }));
vi.mock('js-file-download', () => ({ default: fileDownload }));

import handleExportJson from './ThemeExportHandler';

describe('ThemeExportHandler', () => {
  beforeEach(() => {
    vi.resetAllMocks();
    vi.useFakeTimers({ now: new Date('2026-10-29T10:00:00.000Z') });
  });

  it('downloads the configuration of the theme as JSON, in a file named after the day and the theme', async () => {
    fetchQuery.mockReturnValue({ toPromise: async () => ({ theme: { id: 'theme-id', name: 'Dark', toConfigurationExport: '{"name":"Dark"}' } }) });
    await handleExportJson({ id: 'theme-id', name: 'Dark' } as Parameters<typeof handleExportJson>[0]);
    expect(fetchQuery).toHaveBeenCalledWith(expect.anything(), { id: 'theme-id' });
    expect(fileDownload).toHaveBeenCalledTimes(1);
    const [blob, fileName] = fileDownload.mock.calls[0];
    expect(fileName).toEqual('20261029_octi_theme_dark.json');
    expect(await (blob as Blob).text()).toEqual('{"name":"Dark"}');
  });

  it('downloads nothing when the theme is not found', async () => {
    fetchQuery.mockReturnValue({ toPromise: async () => ({ theme: null }) });
    await handleExportJson({ id: 'missing', name: 'Gone' } as Parameters<typeof handleExportJson>[0]);
    expect(fileDownload).not.toHaveBeenCalled();
  });
});
