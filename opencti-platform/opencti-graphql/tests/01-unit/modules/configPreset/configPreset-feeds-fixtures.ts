import { customMarking } from './configPreset-markings-fixtures';
import { mitreConnectorUser } from './configPreset-connectors-fixtures';

export const securityNewsFeed = {
  id: 'security-news-id',
  internal_id: 'security-news-id',
  standard_id: 'ingestion-rss--11111111-1111-4111-8111-111111111111',
  entity_type: 'IngestionRss',
  created_at: '2026-01-01T00:00:00.000Z',
  name: 'Security news',
  description: 'Daily news',
  scheduling_period: 'PT1H',
  uri: 'https://news.example.com/rss',
  user_id: mitreConnectorUser.id,
  report_types: ['threat-report'],
  object_marking_refs: [customMarking.id],
  current_state_date: '2026-03-01T00:00:00.000Z',
  ingestion_running: true,
};

export const otherSecurityNewsFeed = {
  ...securityNewsFeed,
  id: 'other-security-news-id',
  internal_id: 'other-security-news-id',
  standard_id: 'ingestion-rss--22222222-2222-4222-8222-222222222222',
  created_at: '2026-02-01T00:00:00.000Z',
  uri: 'https://other-news.example.com/rss',
  object_marking_refs: [],
};

export const partnerTaxiiFeed = {
  id: 'partner-taxii-id',
  internal_id: 'partner-taxii-id',
  standard_id: 'ingestion-taxii--33333333-3333-4333-8333-333333333333',
  entity_type: 'IngestionTaxii',
  created_at: '2026-01-01T00:00:00.000Z',
  name: 'Partner/TAXII',
  uri: 'https://taxii.example.com',
  version: 'v21',
  collection: 'collection-id',
  authentication_type: 'basic',
  authentication_value: 'encrypted-credentials',
  current_state_cursor: 'cursor',
  ingestion_running: false,
};

export const ALL_RSS_FEEDS = [otherSecurityNewsFeed, securityNewsFeed];
export const ALL_TAXII_FEEDS = [partnerTaxiiFeed];
