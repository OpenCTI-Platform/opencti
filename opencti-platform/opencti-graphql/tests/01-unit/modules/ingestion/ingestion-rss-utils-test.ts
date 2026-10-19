import { describe, expect, it, vi } from 'vitest';
import TurndownService from 'turndown';
import { buildRssReportsBundle, type DataItem, rssDataParser, rssHttpClientOptions, rssHttpGetter } from '../../../../src/modules/ingestion/ingestion-rss-utils';
import { FEED_REQUEST_TIMEOUT } from '../../../../src/modules/ingestion/ingestion-common';
import type { BasicStoreEntityIngestionRss } from '../../../../src/modules/ingestion/ingestion-types';
import { getHttpClient } from '../../../../src/utils/http-client';
import { utcDate } from '../../../../src/utils/format';

vi.mock('../../../../src/utils/http-client', async (importOriginal) => {
  const original = await importOriginal<typeof import('../../../../src/utils/http-client')>();
  return { ...original, getHttpClient: vi.fn() };
});

const buildIngestion = (overrides: Partial<BasicStoreEntityIngestionRss> = {}) => ({
  name: 'My feed',
  uri: 'https://feed.example.com/rss',
  created_by_ref: 'identity--5b4c1a5e-5a1b-4b3e-9d6c-0f8b6f6a3b11',
  object_marking_refs: ['marking-definition--613f2e26-407d-48c7-9eca-b8e91df99dc9'],
  report_types: ['threat-report'],
  ...overrides,
} as unknown as BasicStoreEntityIngestionRss);

const rss2 = (items: string) => `<?xml version="1.0"?><rss version="2.0"><channel><title>Feed</title>${items}</channel></rss>`;

describe('ingestion-rss-utils', () => {
  describe('rssDataParser', () => {
    const turndownService = new TurndownService();

    it('should keep only items published after the current state date, oldest first', async () => {
      const xml = rss2(`
        <item><title>Newest</title><pubDate>Wed, 03 Jan 2024 10:00:00 GMT</pubDate></item>
        <item><title>Too old</title><pubDate>Mon, 01 Jan 2024 10:00:00 GMT</pubDate></item>
        <item><title>Middle</title><pubDate>Tue, 02 Jan 2024 10:00:00 GMT</pubDate></item>
      `);
      const items = await rssDataParser(turndownService, xml, new Date('2024-01-01T12:00:00.000Z'));
      expect(items.map((i) => i.title)).toEqual(['Middle', 'Newest']);
    });

    it('should drop items whose date cannot be parsed', async () => {
      const xml = rss2(`
        <item><title>Valid</title><pubDate>Tue, 02 Jan 2024 10:00:00 GMT</pubDate></item>
        <item><title>Invalid</title><pubDate>not a date</pubDate></item>
      `);
      const items = await rssDataParser(turndownService, xml, undefined);
      expect(items.map((i) => i.title)).toEqual(['Valid']);
    });

    it('should use the link, then "Untitled", when an item has no title', async () => {
      const xml = rss2(`
        <item><link>https://feed.example.com/a</link><pubDate>Tue, 02 Jan 2024 10:00:00 GMT</pubDate></item>
        <item><pubDate>Wed, 03 Jan 2024 10:00:00 GMT</pubDate></item>
      `);
      const items = await rssDataParser(turndownService, xml, undefined);
      expect(items.map((i) => i.title)).toEqual(['https://feed.example.com/a', 'Untitled']);
      expect(items[1].link).toBeUndefined();
    });

    it('should accept a single category as well as several, without duplicates', async () => {
      const xml = rss2(`
        <item><title>One</title><category> APT </category><pubDate>Tue, 02 Jan 2024 10:00:00 GMT</pubDate></item>
        <item><title>Many</title><category>APT</category><category>Malware</category><category>APT</category><pubDate>Wed, 03 Jan 2024 10:00:00 GMT</pubDate></item>
      `);
      const items = await rssDataParser(turndownService, xml, undefined);
      expect(items[0].labels).toEqual(['APT']);
      expect(items[1].labels).toEqual(['APT', 'Malware']);
    });

    it('should fall back to the channel date when an item has no date', async () => {
      const xml = `<?xml version="1.0"?><rss version="2.0"><channel><pubDate>Tue, 02 Jan 2024 10:00:00 GMT</pubDate><item><title>No date</title></item></channel></rss>`;
      const items = await rssDataParser(turndownService, xml, undefined);
      expect(items[0].pubDate.toISOString()).toBe('2024-01-02T10:00:00.000Z');
    });

    it('should read the Atom link from its href attribute and convert the summary to markdown', async () => {
      const xml = `<?xml version="1.0"?><feed xmlns="http://www.w3.org/2005/Atom">
        <entry><title>Entry</title><link href="https://feed.example.com/entry"/><summary>&lt;b&gt;Bold&lt;/b&gt;</summary><updated>2024-01-02T10:00:00Z</updated></entry>
      </feed>`;
      const items = await rssDataParser(turndownService, xml, undefined);
      expect(items).toHaveLength(1);
      expect(items[0].link).toBe('https://feed.example.com/entry');
      expect(items[0].description).toBe('**Bold**');
      expect(items[0].labels).toEqual([]);
    });

    it('should return no item for a document that is neither RSS nor Atom', async () => {
      const items = await rssDataParser(turndownService, '<?xml version="1.0"?><html><body/></html>', undefined);
      expect(items).toEqual([]);
    });
  });

  describe('rssHttpClientOptions', () => {
    it('should request text with the feed timeout and a browser user agent', () => {
      const options = rssHttpClientOptions(buildIngestion());
      expect(options.responseType).toBe('text');
      expect(options.timeout).toBe(FEED_REQUEST_TIMEOUT);
      expect(options.headers?.['User-Agent']).toEqual(expect.any(String));
    });

    it('should not verify SSL unless the feed asks for it', () => {
      expect(rssHttpClientOptions(buildIngestion()).rejectUnauthorized).toBe(false);
      expect(rssHttpClientOptions(buildIngestion({ ssl_verify: true })).rejectUnauthorized).toBe(true);
    });
  });

  describe('rssHttpGetter', () => {
    it('should fetch the uri with the RSS options and return the response body', async () => {
      const get = vi.fn().mockResolvedValue({ data: '<rss/>' });
      vi.mocked(getHttpClient).mockReturnValue({ get } as unknown as ReturnType<typeof getHttpClient>);
      const ingestion = buildIngestion();

      const data = await rssHttpGetter(ingestion)('https://feed.example.com/rss');

      expect(getHttpClient).toHaveBeenCalledWith(rssHttpClientOptions(ingestion));
      expect(get).toHaveBeenCalledWith('https://feed.example.com/rss');
      expect(data).toBe('<rss/>');
    });
  });

  describe('buildRssReportsBundle', () => {
    const item = (overrides: Partial<DataItem> = {}): DataItem => ({
      title: 'Report title',
      description: 'Report description',
      link: 'https://feed.example.com/report',
      content: '',
      labels: ['APT'],
      pubDate: utcDate('2024-01-02T10:00:00.000Z'),
      ...overrides,
    });

    it('should build one STIX report per item, carrying the feed settings', () => {
      const ingestion = buildIngestion();
      const bundle = buildRssReportsBundle(ingestion, [item()]);

      expect(bundle.type).toBe('bundle');
      expect(bundle.spec_version).toBe('2.1');
      expect(bundle.id).toMatch(/^bundle--/);
      expect(bundle.objects).toHaveLength(1);
      expect(bundle.objects[0]).toMatchObject({
        type: 'report',
        name: 'Report title',
        description: 'Report description',
        labels: ['APT'],
        published: '2024-01-02T10:00:00.000Z',
        created_by_ref: ingestion.created_by_ref,
        object_marking_refs: ingestion.object_marking_refs,
        report_types: ingestion.report_types,
        external_references: [{
          source_name: 'Report title',
          description: 'My feed Report title. Retrieved 2024-01-02T10:00:00.000Z.',
          url: 'https://feed.example.com/report',
        }],
      });
      expect(bundle.objects[0].id).toMatch(/^report--/);
    });

    it('should give the same report id to the same item, so a re-fetched item is upserted', () => {
      const first = buildRssReportsBundle(buildIngestion(), [item()]);
      const second = buildRssReportsBundle(buildIngestion(), [item()]);
      expect(first.objects[0].id).toBe(second.objects[0].id);
      expect(first.id).not.toBe(second.id);
    });

    it('should not add an external reference when the item has no link', () => {
      const bundle = buildRssReportsBundle(buildIngestion(), [item({ link: undefined })]);
      expect(bundle.objects[0]).not.toHaveProperty('external_references');
    });
  });
});
