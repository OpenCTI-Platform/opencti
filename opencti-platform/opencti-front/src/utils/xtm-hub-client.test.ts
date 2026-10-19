import { describe, expect, it } from 'vitest';
import { getXtmHubOrigin } from './xtm-hub-client';

describe('Function: getXtmHubOrigin', () => {
  it('returns null when the Hub URL is not set', () => {
    expect(getXtmHubOrigin(undefined)).toBeNull();
    expect(getXtmHubOrigin(null)).toBeNull();
    expect(getXtmHubOrigin('')).toBeNull();
  });

  it('returns null when the Hub URL is not a valid absolute URL', () => {
    expect(getXtmHubOrigin('hub.filigran.io')).toBeNull();
    expect(getXtmHubOrigin('/app')).toBeNull();
  });

  it('keeps only the origin of the Hub URL', () => {
    expect(getXtmHubOrigin('https://hub.filigran.io/app')).toBe('https://hub.filigran.io');
    expect(getXtmHubOrigin('https://hub.filigran.io/app/?x=1#y')).toBe('https://hub.filigran.io');
  });

  it('keeps the port and normalizes the host and default port', () => {
    expect(getXtmHubOrigin('http://localhost:3002/')).toBe('http://localhost:3002');
    expect(getXtmHubOrigin('HTTPS://Hub.Filigran.io:443/app')).toBe('https://hub.filigran.io');
  });
});
