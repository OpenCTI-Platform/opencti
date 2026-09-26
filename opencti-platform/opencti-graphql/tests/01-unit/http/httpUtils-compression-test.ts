import { describe, expect, it } from 'vitest';
import type { Response } from 'express';
import { isResponseWorthCompressing } from '../../../src/http/httpUtils';

const responseWith = (contentType?: string) => ({
  getHeader: () => contentType,
}) as unknown as Response;

describe('isResponseWorthCompressing', () => {
  it('should refuse server-sent events, which must not be buffered', () => {
    expect(isResponseWorthCompressing(responseWith('text/event-stream'))).toBe(false);
  });

  it('should refuse server-sent events as the platform actually announces them', () => {
    // src/graphql/sseMiddleware.js sends the charset parameter
    expect(isResponseWorthCompressing(responseWith('text/event-stream; charset=utf-8'))).toBe(false);
  });

  it('should ignore case and surrounding spaces in the media type', () => {
    expect(isResponseWorthCompressing(responseWith('Application/Octet-Stream ; x=1'))).toBe(false);
  });

  it('should refuse octet-stream, whose content is unknown and in practice already compressed', () => {
    expect(isResponseWorthCompressing(responseWith('application/octet-stream'))).toBe(false);
  });

  it('should refuse octet-stream carrying a parameter', () => {
    expect(isResponseWorthCompressing(responseWith('application/octet-stream; charset=binary'))).toBe(false);
  });

  it('should accept the types the middleware can usefully compress', () => {
    for (const contentType of ['application/json', 'text/html', 'text/csv', 'application/xml']) {
      expect(isResponseWorthCompressing(responseWith(contentType))).toBe(true);
    }
  });

  it('should leave the decision to the middleware when no type is set', () => {
    expect(isResponseWorthCompressing(responseWith(undefined))).toBe(true);
  });
});
