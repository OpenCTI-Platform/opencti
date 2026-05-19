import { act } from '@testing-library/react';
import { beforeEach, describe, expect, it, vi } from 'vitest';
import { testRenderHook } from '../../../../utils/tests/test-render';
import useMarkdownImages from './useMarkdownImages';

const finalizeTempImageUrlsMock = vi.fn();

vi.mock('./useMarkdownImagesUpload', () => ({
  default: () => ({
    finalizeTempImageUrls: finalizeTempImageUrlsMock,
  }),
}));

const buildHookArgs = () => ({
  activeTab: 'write' as const,
  disabled: false,
  t_i18n: (value: string) => value,
  containerRef: { current: null },
  value: '',
  onValueChange: vi.fn(),
  setDraftValue: vi.fn(),
  pushDraftValue: vi.fn(),
  isFieldFocusedRef: { current: false },
  registerMarkdownImagesController: undefined,
  uploadEntityId: 'entity-id',
  uploadFileMarkings: [],
  tempCleanupDelayMs: 300,
  maxImageSizeBytes: 5 * 1024 * 1024,
});

describe('Hook: useMarkdownImages', () => {
  beforeEach(() => {
    vi.restoreAllMocks();
    finalizeTempImageUrlsMock.mockReset();
    finalizeTempImageUrlsMock.mockImplementation(async (markdown: string) => markdown);
  });

  it('uses latest synced markdown when finalizeMarkdown is called without explicit markdown argument', async () => {
    const args = buildHookArgs();
    const { hook } = testRenderHook(() => useMarkdownImages(args));

    act(() => {
      hook.result.current.syncLatestMarkdown('typed markdown');
    });

    await act(async () => {
      await hook.result.current.finalizeMarkdown();
    });

    expect(finalizeTempImageUrlsMock).toHaveBeenCalled();
    expect(finalizeTempImageUrlsMock.mock.calls[0][0]).toBe('typed markdown');
  });

  it('removes finalized token from pending cleanup map and temp registry', async () => {
    vi.spyOn(URL, 'createObjectURL').mockReturnValue('blob:token');
    vi.spyOn(URL, 'revokeObjectURL').mockImplementation(() => undefined);
    vi.spyOn(globalThis.crypto, 'randomUUID').mockReturnValue('11111111-1111-1111-1111-111111111111');

    const args = buildHookArgs();
    const { hook } = testRenderHook(() => useMarkdownImages(args));

    const file = new File(['file-content'], 'finalize.png', { type: 'image/png' });
    let timeoutId: ReturnType<typeof setTimeout> | undefined;
    let token = '';

    act(() => {
      const attachment = hook.result.current.registryRef.current.createTempAttachment(file);
      token = attachment.token;
      timeoutId = setTimeout(() => undefined, 1000);
      hook.result.current.pendingCleanupTimeoutRef.current.set(token, timeoutId);
    });

    finalizeTempImageUrlsMock.mockImplementationOnce(async (
      markdown: string,
      _registry: unknown,
      onTokenFinalized: (tokenValue: string) => void,
    ) => {
      onTokenFinalized(token);
      return markdown;
    });

    await act(async () => {
      await hook.result.current.finalizeMarkdown('prefix');
    });

    expect(hook.result.current.pendingCleanupTimeoutRef.current.has(token)).toBe(false);
    expect(hook.result.current.registryRef.current.getAttachment(token)).toBeUndefined();

    if (timeoutId) {
      clearTimeout(timeoutId);
    }
  });
});
