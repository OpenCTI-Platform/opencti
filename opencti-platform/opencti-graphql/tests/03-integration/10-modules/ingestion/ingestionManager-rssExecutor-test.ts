import { describe, expect, it, vi } from 'vitest';
import { rssExecutor } from '../../../../src/manager/ingestionManager';
import { ADMIN_USER, testContext } from '../../../utils/testQuery';
import { type IngestionRssAddInput } from '../../../../src/generated/graphql';
import * as mockConnector from '../../../../src/domain/connector';
import TurndownService from 'turndown';
import { addIngestion as addIngestionRss, findById as findIngestionRssById } from '../../../../src/modules/ingestion/ingestion-rss-domain';
import type { BasicStoreEntityIngestionRss } from '../../../../src/modules/ingestion/ingestion-types';

type Getter = (uri: string) => Promise<object>;

const rssFeedContent = `
<rss xmlns:dc="http://purl.org/dc/elements/1.1/" version="2.0">
<channel>
<title>Security Research | Blog</title>
<link>https://www.zscaler.com/blogs/feeds/security-research</link>
<description>Latest news and views from the leading voices in cloud security and secure digital transformation.</description>
<lastBuildDate>Mon, 25 May 2026 15:07:13 GMT</lastBuildDate>
<docs>https://validator.w3.org/feed/docs/rss2.html</docs>
<generator>RSS 2.0, JSON Feed 1.0, and Atom 1.0 generator for Node.js</generator>
<language>en</language>
<item>
<title>
<![CDATA[ When the Scanner Starts Thinking: Learnings from Mythos &amp; GPT 5.5 Cyber in Security Testing ]]>
</title>
<link>https://www.zscaler.com/blogs/security-research/when-scanner-starts-thinking-learnings-mythos-gpt-5-5-cyber-security</link>
<guid>https://www.zscaler.com/blogs/security-research/when-scanner-starts-thinking-learnings-mythos-gpt-5-5-cyber-security</guid>
<pubDate>Fri, 22 May 2026 18:44:14 GMT</pubDate>
<description>
<![CDATA[ Dummy description ]]>
</description>
<dc:creator>Deepen Desai (EVP, Chief Security Officer)</dc:creator>
</item>
`;

// TODO I need to go back to tests coverage.
describe.skip('Verify RSS ingestion with httpClient and queue mocked', () => {
  it('should rssExecutor run on one ingestion', async () => {
    const turndownService = new TurndownService();
    vi.spyOn(mockConnector, 'queueDetails').mockResolvedValue({ messages_number: 0, messages_size: 0 });
    vi.spyOn(mockConnector, 'connectorIdFromIngestId').mockResolvedValue('connector-id-rss-fake');

    const ingestionRssInput: IngestionRssAddInput = {
      ingestion_running: true,
      name: 'Rss ingestion ssl_verify true',
      uri: 'https://test.invalid',
      user_id: ADMIN_USER.id,
      ssl_verify: true,
    };
    const ingestion = await addIngestionRss(testContext, ADMIN_USER, ingestionRssInput);
    expect(ingestion.id).toBeDefined();

    const rssHttpGetter = (ingestion: BasicStoreEntityIngestionRss): Getter => {
      return async (uri: string) => {
        return { data: rssFeedContent };
      };
    };
    const httpGet = rssHttpGetter(ingestion);

    const basicStoreingestion = await findIngestionRssById(testContext, ADMIN_USER, ingestion.id);
    expect(basicStoreingestion.ssl_verify).toBe(true);

    await rssExecutor(testContext, turndownService);
  });
});
