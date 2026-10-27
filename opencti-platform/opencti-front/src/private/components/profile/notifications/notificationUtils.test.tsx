import { describe, expect, it } from 'vitest';
import { computeNotificationLink } from './notificationUtils';

describe('computeNotificationLink', () => {
  it.each([
    ['Connector', '/dashboard/integrations/connectors/id-1'],
    ['Sync', '/dashboard/integrations/feeds/sync/id-1'],
    ['IngestionRss', '/dashboard/integrations/feeds/rss/id-1'],
    ['IngestionTaxii', '/dashboard/integrations/feeds/taxii/id-1'],
    ['IngestionTaxiiCollection', '/dashboard/integrations/feeds/taxii-push/id-1'],
    ['IngestionCsv', '/dashboard/integrations/feeds/csv/id-1'],
    ['IngestionJson', '/dashboard/integrations/feeds/json/id-1'],
    ['DraftWorkspace', '/dashboard/data/import/draft/id-1'],
    ['Report', '/dashboard/id/id-1'],
    [null, '/dashboard/id/id-1'],
  ])('should link a %s notification to its page', (entityType, expected) => {
    expect(computeNotificationLink('id-1', entityType)).toBe(expected);
  });
});
