import fs from 'node:fs';
import { describe, expect, it } from 'vitest';
import TurndownService from 'turndown';
import { rssDataParser } from '../../../src/manager/ingestionManager';

describe('Rss parsing testing', () => {
  it('should oracleRss 2.0 parsed correctly', async () => {
    const rssFeed = fs.readFileSync('./tests/data/rss-feeds/rss-oracle.xml', { encoding: 'utf8', flag: 'r' });
    const turndownService = new TurndownService();
    const items = await rssDataParser(turndownService, rssFeed, undefined);
    expect(items.length).toBe(1);
    expect(items[0].pubDate.toISOString()).toBe('1970-01-01T00:00:00.000Z');
  });
  it('should citrixRss 2.0 parsed correctly', async () => {
    const rssFeed = fs.readFileSync('./tests/data/rss-feeds/rss-citrix.xml', { encoding: 'utf8', flag: 'r' });
    const turndownService = new TurndownService();
    const items = await rssDataParser(turndownService, rssFeed, undefined);
    expect(items.length).toBe(1);
    expect(items[0].labels.length).toBe(2);
    expect(items[0].labels).toEqual(['ShareFile', 'Citrix Content Collaboration']);
  });
  it('should googleAtom 1.0 parsed correctly', async () => {
    const rssFeed = fs.readFileSync('./tests/data/rss-feeds/rss-google.xml', { encoding: 'utf8', flag: 'r' });
    const turndownService = new TurndownService();
    const items = await rssDataParser(turndownService, rssFeed, undefined);
    expect(items.length).toBe(1);
    expect(items[0].labels.length).toBe(0);
  });
  it('should secureList 2.0 parsed correctly', async () => {
    const rssFeed = fs.readFileSync('./tests/data/rss-feeds/rss-securelist.xml', { encoding: 'utf8', flag: 'r' });
    const turndownService = new TurndownService();
    const items = await rssDataParser(turndownService, rssFeed, undefined);
    expect(items.length).toBe(1);
    expect(items[0].labels.length).toBe(8);
    expect(items[0].link).toBe('https://securelist.com/focus-on-droxidat-systembc/110302/');
    expect(items[0].description).toBe('An unknown actor targeted an electric utility in southern Africa with Cobalt Strike beacons and DroxiDat, a new variant of the SystemBC payload. We speculate that this incident was in the initial stages of a ransomware attack.');
    expect(items[0].content).toBeDefined();
  });
  it('should wago parsed correctly', async () => {
    const rssFeed = fs.readFileSync('./tests/data/rss-feeds/rss-wago.xml', { encoding: 'utf8', flag: 'r' });
    const turndownService = new TurndownService();
    const items = await rssDataParser(turndownService, rssFeed, undefined);
    expect(items.length).toBe(43); // 44 minus 1 with empty title
    expect(items[0].labels.length).toBe(0);
    expect(items[0].link).toBe('https://cert.vde.com/de-de/advisories/vde-2018-010');
    expect(items[0].description).toBe('An unauthenticated user can exploit a vulnerability (CVE-2018-12981) to inject code in the WBM via reflected cross-site scripting (XSS), if he is able trick a user to open a special crafted web site. \\[...\\]');
    expect(items[0].content).toBeDefined();
  });
});
