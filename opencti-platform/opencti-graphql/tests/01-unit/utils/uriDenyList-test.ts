import { beforeEach, describe, expect, it, vi } from 'vitest';

import { verifyUri } from '../../../src/utils/uriDenyList';
import * as uriDenyListConfig from '../../../src/config/uriDenyList';

describe('URI deny list coverage', () => {
  beforeEach(() => {
    vi.clearAllMocks();
    vi.restoreAllMocks();
  });

  it('should allow any URI', () => {
    vi.spyOn(uriDenyListConfig, 'uriDenyList').mockReturnValue([]);
    expect(() => verifyUri('https://example.com/feed.csv')).not.toThrow();
    expect(() => verifyUri('http://localhost:4200/data')).not.toThrow();
  });

  it('should block URI matching an exact domain in deny list', () => {
    vi.spyOn(uriDenyListConfig, 'uriDenyList').mockReturnValue(['mydomain.com']);
    expect(() => verifyUri('https://mydomain.com/feed.csv')).toThrow('This URI is not allowed.');
    expect(() => verifyUri('https://mydomain.com:8080/feed.csv')).toThrow('This URI is not allowed.');
    expect(() => verifyUri('https://sub.mydomain.com/feed.csv')).not.toThrow();
    expect(() => verifyUri('https://otherdomain.com/feed.csv')).not.toThrow();
  });

  it('should block subdomains matching wildcard pattern', () => {
    vi.spyOn(uriDenyListConfig, 'uriDenyList').mockReturnValue(['*.mydomain.com']);
    expect(() => verifyUri('https://sub.mydomain.com/feed.csv')).toThrow('This URI is not allowed.');
    expect(() => verifyUri('https://deep.sub.mydomain.com/feed.csv')).toThrow('This URI is not allowed.');
    expect(() => verifyUri('https://deep.sub.mydomain.com:8080/feed.csv')).toThrow('This URI is not allowed.');
    expect(() => verifyUri('https://mydomain.com/feed.csv')).toThrow('This URI is not allowed.');
    expect(() => verifyUri('https://otherdomain.com/feed.csv')).not.toThrow();
  });

  it('should block URI matching host:port pattern', () => {
    vi.spyOn(uriDenyListConfig, 'uriDenyList').mockReturnValue(['localhost:4200']);
    expect(() => verifyUri('http://localhost:4200/data')).toThrow('This URI is not allowed.');
    expect(() => verifyUri('http://localhost:8080/data')).not.toThrow();
    expect(() => verifyUri('http://localhost/data')).not.toThrow();
  });

  it('should match regardless of case', () => {
    vi.spyOn(uriDenyListConfig, 'uriDenyList').mockReturnValue(['MyDomain.COM']);
    expect(() => verifyUri('https://MYDOMAIN.com/feed.csv')).toThrow('This URI is not allowed.');
  });

  it('should block if any entry matches', () => {
    vi.spyOn(uriDenyListConfig, 'uriDenyList').mockReturnValue(['allowed.com', 'blocked.com', '*.evil.org']);
    expect(() => verifyUri('https://blocked.com/feed')).toThrow('This URI is not allowed.');
    expect(() => verifyUri('https://sub.evil.org/feed')).toThrow('This URI is not allowed.');
    expect(() => verifyUri('https://allowed.com/feed')).toThrow('This URI is not allowed.');
    expect(() => verifyUri('https://safe.com/feed')).not.toThrow();
    expect(() => verifyUri('blocked.com/path/to/feed')).toThrow('This URI is not allowed.');
  });
});


