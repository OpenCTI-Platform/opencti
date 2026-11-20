import { describe, expect, it } from 'vitest';
import {
  encodeUriCredential,
  isSameUriDestination,
  isSensitiveParameterName,
  sanitizeExportedUri,
  uriCredentials,
  uriWithCredentials,
} from '../../../../src/modules/ingestion/ingestion-uri-credentials';
import { sanitizeExportedQueryAttributes } from '../../../../src/modules/ingestion/ingestion-json-domain';

const roundTrip = (uri: string) => {
  const exported = sanitizeExportedUri(uri);
  const values = Object.fromEntries(uriCredentials(exported, uri).map(({ key, stored }) => [key, stored]));
  return { exported, imported: uriWithCredentials(exported, values) };
};

describe('isSensitiveParameterName', () => {
  it('compares the words of the name, not substrings', () => {
    ['api_key', 'apiKey', 'apikey', 'X-Api-Key', 'access_token', 'page_token', 'key', 'password', 'client_secret'].forEach((name) => {
      expect(isSensitiveParameterName(name), name).toBe(true);
    });
    ['sort_key', 'keyword', 'monkey', 'limit', 'offset', 'tokenizer_mode'].forEach((name) => {
      expect(isSensitiveParameterName(name), name).toBe(false);
    });
  });
});

describe('sanitizeExportedUri', () => {
  it('blanks the password and the sensitive parameters, and leaves the rest of the URI as written', () => {
    expect(sanitizeExportedUri('https://reader:p%40ss@api.example.com/feed?q=a%20b&flag&api_key=X&tag=1&tag=2&offset=$offset#top'))
      .toEqual('https://reader:@api.example.com/feed?q=a%20b&flag&api_key=&tag=1&tag=2&offset=$offset#top');
  });

  it('leaves a user without password, which can be a token, and a URI without secret unchanged', () => {
    expect(sanitizeExportedUri('https://TOKEN@host.example.com/f.csv')).toEqual('https://TOKEN@host.example.com/f.csv');
    expect(sanitizeExportedUri('https://host.example.com/f.csv?sort_key=name&next_token=')).toEqual('https://host.example.com/f.csv?sort_key=name&next_token=');
  });
});

describe('export then import of a URI', () => {
  it.each([
    'https://reader:p%40ss@api.example.com/feed?q=a%20b&flag&api_key=X%2BY&tag=1&tag=2&offset=$offset',
    'https://api.example.com/feed?api_key=X&offset=$offset',
    'https://TOKEN@host.example.com/f.csv',
    'https://host.example.com/f.csv?next_token=',
  ])('gives back %s on the platform that holds it', (uri) => {
    expect(roundTrip(uri).imported).toEqual(uri);
  });

  it('offers the blank values only, a token as user name being none, and tells what the target holds', () => {
    expect(uriCredentials('https://TOKEN@host.example.com/f.csv?next_token=').map(({ key, stored }) => [key, stored])).toEqual([['uri:query:next_token', '']]);
    expect(uriCredentials('https://host.example.com/f.csv?next_token=', 'https://host.example.com/f.csv?next_token=abc').map(({ stored }) => stored)).toEqual(['abc']);
    expect(uriCredentials(sanitizeExportedUri('https://reader:pw@api.example.com/feed?api_key=X')).map(({ key, stored }) => [key, stored]))
      .toEqual([['uri:password', ''], ['uri:query:api_key', '']]);
  });

  it('writes a given value encoded, in the blanked parameter only', () => {
    const exported = sanitizeExportedUri('https://api.example.com/feed?api_key=X&offset=$offset');
    expect(uriWithCredentials(exported, { 'uri:query:api_key': encodeUriCredential('a b&c') })).toEqual('https://api.example.com/feed?api_key=a%20b%26c&offset=$offset');
  });
});

describe('isSameUriDestination', () => {
  it('compares the scheme, the host and the port', () => {
    expect(isSameUriDestination('https://api.example.com/a', 'https://api.example.com/b?x=1')).toBe(true);
    expect(isSameUriDestination('https://api.example.com/a', 'https://other.example.com/a')).toBe(false);
    expect(isSameUriDestination('https://api.example.com/a', 'https://api.example.com:8443/a')).toBe(false);
  });

  it('never keeps the credentials for a URI whose authority holds a variable', () => {
    expect(isSameUriDestination('https://$h:x@api.good.com/feed', 'https://$h:x@api.good.com/feed')).toBe(false);
    expect(isSameUriDestination('https://api.good.com/feed', 'https://$h:x@api.good.com/feed')).toBe(false);
  });
});

describe('sanitizeExportedQueryAttributes', () => {
  it('keeps the default of a parameter whose name only contains a sensitive substring, and blanks a sensitive header', () => {
    const attributes = [
      { type: 'data', from: 'sort', to: 'sort_key', default: 'name', exposed: 'query_param' },
      { type: 'data', from: 'kw', to: 'keyword', default: 'apt', exposed: 'body' },
      { type: 'data', from: 'key', to: 'api_key', default: 'secret', exposed: 'query_param' },
      { type: 'header', from: 'x-key', to: 'X-Monkey-Key', default: 'secret', exposed: 'header' },
    ];
    expect(sanitizeExportedQueryAttributes(attributes)?.map(({ default: value }) => value)).toEqual(['name', 'apt', '', '']);
  });
});
