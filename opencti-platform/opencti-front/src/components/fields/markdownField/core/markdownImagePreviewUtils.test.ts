import { beforeEach, describe, expect, it, vi } from 'vitest';
import { MarkdownTempAttachmentRegistry, TEMP_IMAGE_SCHEME, extractTempImageTokens, insertImageAtCursor, replaceTempImageTokenUrl } from './markdownImagePreviewUtils';

describe('markdown temp image utilities', () => {
  beforeEach(() => {
    vi.restoreAllMocks();
  });

  it('extractTempImageTokens returns unique token list from markdown', () => {
    const markdown = [
      'before ![a](opencti-image://temp/11111111-1111-1111-1111-111111111111)',
      'middle ![b](opencti-image://temp/22222222-2222-2222-2222-222222222222)',
      'repeat ![a2](opencti-image://temp/11111111-1111-1111-1111-111111111111)',
    ].join('\n');

    expect(extractTempImageTokens(markdown)).toEqual([
      '11111111-1111-1111-1111-111111111111',
      '22222222-2222-2222-2222-222222222222',
    ]);
  });

  it('replaceTempImageTokenUrl rewrites all occurrences of a token URL', () => {
    const token = '33333333-3333-3333-3333-333333333333';
    const markdown = [
      `![first](opencti-image://temp/${token})`,
      `![second](opencti-image://temp/${token})`,
    ].join('\n');

    const result = replaceTempImageTokenUrl(markdown, token, '/storage/view/import%2Fpending%2Fabc');

    expect(result).toBe([
      '![first](/storage/view/import%2Fpending%2Fabc)',
      '![second](/storage/view/import%2Fpending%2Fabc)',
    ].join('\n'));
  });

  it('insertImageAtCursor_insertsTempImageMarkdownAtCursor', () => {
    const input = 'abc def';
    const cursorIndex = 3;

    const result = insertImageAtCursor(input, cursorIndex, 'tmp-1');

    expect(result.markdown).toBe('abc![image](opencti-image://temp/tmp-1) def');
    expect(result.nextCursor).toBe('abc![image](opencti-image://temp/tmp-1)'.length);
    expect(result.markdown.replace('![image](opencti-image://temp/tmp-1)', '')).toBe(input);
  });

  it('insertImageAtCursor_handlesStartAndEndPositions', () => {
    const input = 'abc def';

    const atStart = insertImageAtCursor(input, 0, 'tmp-start');
    expect(atStart.markdown).toBe('![image](opencti-image://temp/tmp-start)abc def');
    expect(atStart.nextCursor).toBe('![image](opencti-image://temp/tmp-start)'.length);

    const atEnd = insertImageAtCursor(input, input.length, 'tmp-end');
    expect(atEnd.markdown).toBe('abc def![image](opencti-image://temp/tmp-end)');
    expect(atEnd.nextCursor).toBe(
      'abc def![image](opencti-image://temp/tmp-end)'.length,
    );
  });

  it('createTempAttachment_createsUniqueTokenAndBlobUrl', () => {
    const createObjectURL = vi
      .spyOn(URL, 'createObjectURL')
      .mockReturnValueOnce('blob:first')
      .mockReturnValueOnce('blob:second');

    const registry = new MarkdownTempAttachmentRegistry();
    const file = new File(['content'], 'same-name.png', { type: 'image/png' });

    const first = registry.createTempAttachment(file);
    const second = registry.createTempAttachment(file);

    expect(first.token).not.toBe(second.token);
    expect(first.status).toBe('local');
    expect(second.status).toBe('local');
    expect(first.blobUrl).toBe('blob:first');
    expect(second.blobUrl).toBe('blob:second');
    expect(registry.size).toBe(2);
    expect(createObjectURL).toHaveBeenCalledTimes(2);
  });

  it('removeTempAttachment_revokesOnlyRemovedBlobUrl', () => {
    vi.spyOn(URL, 'createObjectURL')
      .mockReturnValueOnce('blob:first')
      .mockReturnValueOnce('blob:second');
    const revokeObjectURL = vi.spyOn(URL, 'revokeObjectURL').mockImplementation(() => undefined);

    const registry = new MarkdownTempAttachmentRegistry();
    const first = registry.createTempAttachment(new File(['first'], 'a.png', { type: 'image/png' }));
    const second = registry.createTempAttachment(new File(['second'], 'b.png', { type: 'image/png' }));

    registry.removeTempAttachment(first.token);

    expect(revokeObjectURL).toHaveBeenCalledTimes(1);
    expect(revokeObjectURL).toHaveBeenCalledWith(first.blobUrl);
    expect(registry.getAttachment(second.token)).toBeDefined();

    registry.removeTempAttachment(first.token);
    expect(revokeObjectURL).toHaveBeenCalledTimes(1);
  });

  it('cleanupAllTempAttachments_revokesAllBlobUrlsOnUnmount', () => {
    vi.spyOn(URL, 'createObjectURL')
      .mockReturnValueOnce('blob:first')
      .mockReturnValueOnce('blob:second')
      .mockReturnValueOnce('blob:third');
    const revokeObjectURL = vi.spyOn(URL, 'revokeObjectURL').mockImplementation(() => undefined);

    const registry = new MarkdownTempAttachmentRegistry();
    registry.createTempAttachment(new File(['first'], 'a.png', { type: 'image/png' }));
    registry.createTempAttachment(new File(['second'], 'b.png', { type: 'image/png' }));
    registry.createTempAttachment(new File(['third'], 'c.png', { type: 'image/png' }));

    registry.cleanupAllTempAttachments();

    expect(revokeObjectURL).toHaveBeenCalledTimes(3);
    expect(registry.size).toBe(0);

    registry.cleanupAllTempAttachments();
    expect(revokeObjectURL).toHaveBeenCalledTimes(3);
  });

  it('previewResolver_resolvesTempTokenToBlobUrlAndLeavesNormalUrlsUntouched', () => {
    vi.spyOn(URL, 'createObjectURL').mockReturnValue('blob:first');

    const registry = new MarkdownTempAttachmentRegistry();
    const attachment = registry.createTempAttachment(new File(['first'], 'a.png', { type: 'image/png' }));

    const tempUrl = `${TEMP_IMAGE_SCHEME}${attachment.token}`;
    const persistedUrl = '/storage/view/some-protected-id';
    const unknownTempUrl = `${TEMP_IMAGE_SCHEME}unknown-token`;

    expect(registry.resolvePreviewImageUrl(tempUrl)).toBe(attachment.blobUrl);
    expect(registry.resolvePreviewImageUrl(persistedUrl)).toBe(persistedUrl);
    expect(registry.resolvePreviewImageUrl(unknownTempUrl)).toBeNull();
  });
});
