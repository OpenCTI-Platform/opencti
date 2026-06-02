import { beforeEach, describe, expect, it, vi } from 'vitest';

import { verifyIngestionUri } from '../../../../src/modules/ingestion/ingestion-common';
import * as ingestionConfigurationMock from '../../../../src/manager/ingestionManager/ingestionManagerConfiguration';

describe('Ingestion URI deny list coverage', () => {
  beforeEach(() => {
    vi.clearAllMocks();
    vi.restoreAllMocks();
  });

  it('should allow any URI', () => {
    vi.spyOn(ingestionConfigurationMock, 'ingestionUriDenyList').mockReturnValue([]);
    expect(() => verifyIngestionUri('https://example.com/feed.csv')).not.toThrow();
    expect(() => verifyIngestionUri('http://localhost:4200/data')).not.toThrow();
  });

  it('should block URI matching an exact domain in deny list', () => {
    vi.spyOn(ingestionConfigurationMock, 'ingestionUriDenyList').mockReturnValue(['mydomain.com']);
    expect(() => verifyIngestionUri('https://mydomain.com/feed.csv')).toThrow('This URI is not allowed for ingestion.');
    expect(() => verifyIngestionUri('https://sub.mydomain.com/feed.csv')).not.toThrow();
    expect(() => verifyIngestionUri('https://otherdomain.com/feed.csv')).not.toThrow();
  });

  it('should block subdomains matching wildcard pattern', () => {
    vi.spyOn(ingestionConfigurationMock, 'ingestionUriDenyList').mockReturnValue(['*.mydomain.com']);
    expect(() => verifyIngestionUri('https://sub.mydomain.com/feed.csv')).toThrow('This URI is not allowed for ingestion.');
    expect(() => verifyIngestionUri('https://deep.sub.mydomain.com/feed.csv')).toThrow('This URI is not allowed for ingestion.');
    expect(() => verifyIngestionUri('https://mydomain.com/feed.csv')).toThrow('This URI is not allowed for ingestion.');
    expect(() => verifyIngestionUri('https://otherdomain.com/feed.csv')).not.toThrow();
  });

  it('should block URI matching host:port pattern', () => {
    vi.spyOn(ingestionConfigurationMock, 'ingestionUriDenyList').mockReturnValue(['localhost:4200']);
    expect(() => verifyIngestionUri('http://localhost:4200/data')).toThrow('This URI is not allowed for ingestion.');
    expect(() => verifyIngestionUri('http://localhost:8080/data')).not.toThrow();
    expect(() => verifyIngestionUri('http://localhost/data')).not.toThrow();
  });

  it('should match regardless of case', () => {
    vi.spyOn(ingestionConfigurationMock, 'ingestionUriDenyList').mockReturnValue(['MyDomain.COM']);
    expect(() => verifyIngestionUri('https://MYDOMAIN.com/feed.csv')).toThrow('This URI is not allowed for ingestion.');
  });

  it('should block if any entry matches', () => {
    vi.spyOn(ingestionConfigurationMock, 'ingestionUriDenyList').mockReturnValue(['allowed.com', 'blocked.com', '*.evil.org']);
    expect(() => verifyIngestionUri('https://blocked.com/feed')).toThrow('This URI is not allowed for ingestion.');
    expect(() => verifyIngestionUri('https://sub.evil.org/feed')).toThrow('This URI is not allowed for ingestion.');
    expect(() => verifyIngestionUri('https://allowed.com/feed')).toThrow('This URI is not allowed for ingestion.');
    expect(() => verifyIngestionUri('https://safe.com/feed')).not.toThrow();
    expect(() => verifyIngestionUri('blocked.com/path/to/feed')).toThrow('This URI is not allowed for ingestion.');
  });
});
