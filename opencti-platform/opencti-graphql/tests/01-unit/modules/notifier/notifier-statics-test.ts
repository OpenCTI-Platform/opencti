import { describe, expect, it } from 'vitest';
import { HEALTH_EMAIL_TEMPLATE, HEALTH_EMAIL_TITLE } from '../../../../src/modules/notifier/notifier-statics';
import { safeRender } from '../../../../src/utils/safeEjs';
import { sanitizeNotificationData } from '../../../../src/utils/templateContextSanitizer';

const buildTemplateData = (notificationContent: Array<{ title: string; events: Array<{ operation: string; entity_type: string; instance_id: string }> }>) => {
  return sanitizeNotificationData({
    notification_content: notificationContent,
    settings: { platform_title: 'OpenCTI' },
    platform_uri: 'https://opencti.local',
  });
};

describe('Ingestion health default mailer', () => {
  const connectorEvent = { title: 'AlienVault', events: [{ operation: 'critical', entity_type: 'Connector', instance_id: 'connector-id' }] };
  const feedEvent = { title: 'Abuse feed', events: [{ operation: 'recovered', entity_type: 'IngestionTaxiiCollection', instance_id: 'feed-id' }] };

  it('should title a single event with its scope and its ingestion', async () => {
    const rendered = await safeRender(HEALTH_EMAIL_TITLE, buildTemplateData([connectorEvent]));
    expect(rendered).toBe('[health] critical - AlienVault');
  });

  it('should title several events with their count', async () => {
    const rendered = await safeRender(HEALTH_EMAIL_TITLE, buildTemplateData([connectorEvent, feedEvent]));
    expect(rendered).toBe('[health] 2 ingestion health events');
  });

  it('should show the scope, the ingestion and a link to its overview', async () => {
    const rendered = await safeRender(HEALTH_EMAIL_TEMPLATE, buildTemplateData([connectorEvent, feedEvent]));
    expect(rendered).toContain('>critical</span>');
    expect(rendered).toContain('>AlienVault</span>');
    expect(rendered).toContain('(Connector)');
    expect(rendered).toContain('href="https://opencti.local/dashboard/integrations/connectors/connector-id?source=email"');
    expect(rendered).toContain('>recovered</span>');
    expect(rendered).toContain('(TAXII push feed)');
    expect(rendered).toContain('href="https://opencti.local/dashboard/integrations/feeds/taxii-push/feed-id?source=email"');
  });
});
