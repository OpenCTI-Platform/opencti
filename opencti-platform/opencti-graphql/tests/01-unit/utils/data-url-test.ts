import { describe, expect, it } from 'vitest';
import { parseDataUrl } from '../../../src/utils/data-url';

describe('parseDataUrl', () => {
  it('should parse mime type and base64 metadata', () => {
    const parsed = parseDataUrl('data:image/png;base64,Zm9v');
    expect(parsed).toEqual({
      mimeType: 'image/png',
      base64Encoded: true,
      data: 'Zm9v',
    });
  });

  it('should parse metadata case-insensitively for base64 flag', () => {
    const parsed = parseDataUrl('data:image/png;BASE64,Zm9v');
    expect(parsed).toEqual({
      mimeType: 'image/png',
      base64Encoded: true,
      data: 'Zm9v',
    });
  });

  it('should parse URL-encoded payload without base64 flag', () => {
    const parsed = parseDataUrl('data:text/plain,hello%20world');
    expect(parsed).toEqual({
      mimeType: 'text/plain',
      base64Encoded: false,
      data: 'hello%20world',
    });
  });

  it('should fallback when no data URL prefix is present', () => {
    expect(parseDataUrl('https://example.org/logo.png')).toEqual({
      mimeType: '',
      base64Encoded: false,
      data: '',
    });
  });

  it('should fallback when metadata/data separator is missing', () => {
    expect(parseDataUrl('data:image/png;base64')).toEqual({
      mimeType: '',
      base64Encoded: false,
      data: '',
    });
  });
});

