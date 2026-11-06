import { describe, expect, it } from 'vitest';
import { HEALTH_EMAIL_TEMPLATE, HEALTH_EMAIL_TITLE } from '../../../../src/modules/notifier/notifier-statics';
import { safeRender } from '../../../../src/utils/safeEjs';
import { sanitizeNotificationData } from '../../../../src/utils/templateContextSanitizer';

type HealthEvent = { operation: string; entity_type: string; instance_id: string };
type HealthContent = Array<{ title: string; events: HealthEvent[] }>;
// What the health manager puts in the context data of the event
type HealthEventData = {
  ingestion_health_changes?: { message?: string; critical_messages?: string[]; advisory_messages?: string[]; previous_status?: string; status_since?: string };
};

const LIVE = { trigger_type: 'live', name: 'Ingestion health - live alerts' };
const DIGEST = { trigger_type: 'digest', period: 'day', name: 'Ingestion health - daily digest' };

// As given by the publisher manager: the content, and the data it was built from, which carries the context of the health events
const buildTemplateData = (
  notificationContent: HealthContent,
  trigger: { trigger_type: string; period?: string; name?: string } = LIVE,
  eventData: HealthEventData = {},
) => {
  return sanitizeNotificationData({
    notification_content: notificationContent,
    notification: trigger,
    data: notificationContent.flatMap(({ events }) => events.map((event) => ({
      notification_id: 'trigger-id',
      type: event.operation,
      message: '',
      instance: { id: event.instance_id, entity_type: event.entity_type, ...eventData },
    }))),
    settings: { platform_title: 'OpenCTI' },
    platform_uri: 'https://opencti.local',
  });
};

describe('Ingestion health default mailer', () => {
  const connectorEvent = { title: 'AlienVault', events: [{ operation: 'critical', entity_type: 'Connector', instance_id: 'connector-id' }] };
  const feedEvent = { title: 'Abuse feed', events: [{ operation: 'recovered', entity_type: 'IngestionTaxiiCollection', instance_id: 'feed-id' }] };
  const degradedEvent = { title: 'Taxii', events: [{ operation: 'degraded', entity_type: 'IngestionTaxii', instance_id: 'taxii-id' }] };
  const eventData: HealthEventData = {
    ingestion_health_changes: { message: 'Last run failed: HTTP 401 Unauthorized', previous_status: 'healthy', status_since: '2026-10-28T06:14:00.000Z' },
  };

  describe('subject', () => {
    it('should title a live alert with its scope and its ingestion', async () => {
      const rendered = await safeRender(HEALTH_EMAIL_TITLE, buildTemplateData([connectorEvent]));
      expect(rendered).toBe('[live] Critical — AlienVault');
    });

    it('should title several events with the sources needing attention and the ones recovered', async () => {
      const rendered = await safeRender(HEALTH_EMAIL_TITLE, buildTemplateData([connectorEvent, feedEvent, degradedEvent], DIGEST));
      expect(rendered).toBe('[digest] Ingestion health — 2 sources need attention, 1 recovered');
    });

    it('should count a source once in the subject of a digest, even with several events in the period', async () => {
      const degradedThenCritical = { title: 'AlienVault', events: [
        { operation: 'degraded', entity_type: 'Connector', instance_id: 'connector-id' },
        { operation: 'critical', entity_type: 'Connector', instance_id: 'connector-id' },
      ] };
      const rendered = await safeRender(HEALTH_EMAIL_TITLE, buildTemplateData([degradedThenCritical], DIGEST));
      expect(rendered).toBe('[digest] Ingestion health — 1 source needs attention');
    });

    it('should count a source by its last event in the period: recovered after a failure, it no longer needs attention', async () => {
      const criticalThenRecovered = { title: 'Abuse feed', events: [
        { operation: 'critical', entity_type: 'IngestionCsv', instance_id: 'feed-id' },
        { operation: 'recovered', entity_type: 'IngestionCsv', instance_id: 'feed-id' },
      ] };
      const rendered = await safeRender(HEALTH_EMAIL_TITLE, buildTemplateData([criticalThenRecovered, connectorEvent], DIGEST));
      expect(rendered).toBe('[digest] Ingestion health — 1 source needs attention, 1 recovered');
    });

    it('should title a digest as such, even with a single event, and only the non empty counts', async () => {
      const rendered = await safeRender(HEALTH_EMAIL_TITLE, buildTemplateData([connectorEvent], DIGEST));
      expect(rendered).toBe('[digest] Ingestion health — 1 source needs attention');
    });
  });

  describe('live alert', () => {
    it('should show the scope, the source and a link to its overview, without the status change', async () => {
      const rendered = await safeRender(HEALTH_EMAIL_TEMPLATE, buildTemplateData([connectorEvent], LIVE, eventData));
      expect(rendered).toContain('Ingestion health &middot; Live alert</p>');
      expect(rendered).toContain('>Critical</span>');
      expect(rendered).toContain('AlienVault is critical');
      expect(rendered).toContain('AlienVault (Connector)');
      // The previous status is in the event, but the scope tells what happened: no transition shown
      expect(rendered).not.toContain('&rarr;');
      expect(rendered).not.toContain('Status change');
      expect(rendered).toContain('Detected 28 Oct 2026, 06:14 UTC');
      expect(rendered).toContain('Last run failed: HTTP 401 Unauthorized');
      expect(rendered).toContain('href="https://opencti.local/dashboard/integrations/connectors/connector-id?source=email"');
      expect(rendered).toContain('View connector</a>');
    });

    it('should link to the deployed integrations filtered on the critical and degraded sources', async () => {
      const rendered = await safeRender(HEALTH_EMAIL_TEMPLATE, buildTemplateData([connectorEvent]));
      expect(rendered).toContain('href="https://opencti.local/dashboard/integrations/deployed?health=critical,degraded"');
    });

    it('should list the issues of the criticity of the email in its box, without title, and the advisory ones below it', async () => {
      const grouped: HealthEventData = {
        ingestion_health_changes: { critical_messages: ['No heartbeat', 'HTTP 401'], advisory_messages: ['User is not a service account'], status_since: '2026-10-28T06:14:00.000Z' },
      };
      const rendered = await safeRender(HEALTH_EMAIL_TEMPLATE, buildTemplateData([connectorEvent], LIVE, grouped));
      expect(rendered).toMatch(/<li[^>]*>No heartbeat<\/li>\s*<li[^>]*>HTTP 401<\/li>/);
      expect(rendered).toMatch(/Advisory issues<\/p>\s*<p[^>]*>User is not a service account<\/p>/);
      expect(rendered.indexOf('HTTP 401')).toBeLessThan(rendered.indexOf('Advisory issues'));
    });

    it('should show a single issue without bullet point', async () => {
      const grouped: HealthEventData = { ingestion_health_changes: { advisory_messages: ['User is not a service account'] } };
      const rendered = await safeRender(HEALTH_EMAIL_TEMPLATE, buildTemplateData([degradedEvent], LIVE, grouped));
      expect(rendered).toMatch(/<p[^>]*>User is not a service account<\/p>/);
      expect(rendered).not.toContain('<li');
      expect(rendered).not.toContain('Advisory issues');
    });

    it('should name the trigger and link to the alerting settings', async () => {
      const rendered = await safeRender(HEALTH_EMAIL_TEMPLATE, buildTemplateData([connectorEvent]));
      expect(rendered).toContain('a recipient of the trigger &ldquo;Ingestion health - live alerts&rdquo;');
      expect(rendered).toContain('href="https://opencti.local/dashboard/settings/activity/alerting"');
    });

    it('should show a recovery with the view label of its kind, without the status it ends on: healthy or unknown', async () => {
      const rendered = await safeRender(HEALTH_EMAIL_TEMPLATE, buildTemplateData([feedEvent], LIVE, { ingestion_health_changes: { previous_status: 'critical' } }));
      expect(rendered).toContain('Abuse feed has recovered');
      expect(rendered).not.toContain('Healthy');
      expect(rendered).toContain('View feed</a>');
    });

    it('should show neither message, date nor status when the event has no context: the scope alone', async () => {
      const rendered = await safeRender(HEALTH_EMAIL_TEMPLATE, buildTemplateData([connectorEvent]));
      expect(rendered).not.toContain('Detected');
      expect(rendered).not.toContain('>Status</td>');
      expect(rendered).toContain('>Critical</span>');
    });

    it('should not show the sections of a digest', async () => {
      const rendered = await safeRender(HEALTH_EMAIL_TEMPLATE, buildTemplateData([connectorEvent], LIVE, eventData));
      expect(rendered).not.toContain('changed health status');
      expect(rendered).not.toContain('Ingestion health (');
    });
  });

  describe('digest', () => {
    it('should show the scope, the ingestion and a link to its overview', async () => {
      const rendered = await safeRender(HEALTH_EMAIL_TEMPLATE, buildTemplateData([connectorEvent, feedEvent], DIGEST));
      expect(rendered).toContain('>Critical</span>');
      expect(rendered).toContain('>AlienVault</span>');
      expect(rendered).toContain('(Connector)');
      expect(rendered).toContain('href="https://opencti.local/dashboard/integrations/connectors/connector-id?source=email"');
      expect(rendered).toContain('>Recovered</span>');
      expect(rendered).toContain('(TAXII push feed)');
      expect(rendered).toContain('href="https://opencti.local/dashboard/integrations/feeds/taxii-push/feed-id?source=email"');
    });

    it('should show the first issue only, with how many others there are', async () => {
      const grouped: HealthEventData = {
        ingestion_health_changes: { critical_messages: ['No heartbeat', 'HTTP 401'], advisory_messages: ['User is not a service account'] },
      };
      const rendered = await safeRender(HEALTH_EMAIL_TEMPLATE, buildTemplateData([connectorEvent], DIGEST, grouped));
      expect(rendered).toContain('No heartbeat (+2)');
      expect(rendered).not.toContain('HTTP 401');
      expect(rendered).not.toContain('User is not a service account');
    });

    it('should show a single issue without count', async () => {
      const grouped: HealthEventData = { ingestion_health_changes: { critical_messages: ['No heartbeat'] } };
      const rendered = await safeRender(HEALTH_EMAIL_TEMPLATE, buildTemplateData([connectorEvent], DIGEST, grouped));
      expect(rendered).toContain('No heartbeat</div>');
    });

    it('should show its period and how many sources changed', async () => {
      const rendered = await safeRender(HEALTH_EMAIL_TEMPLATE, buildTemplateData([connectorEvent, feedEvent], DIGEST));
      expect(rendered).toContain('Ingestion health &middot; Daily digest &middot;');
      expect(rendered).toContain('2 ingestion sources changed health status in the last day.');
      expect(rendered).toContain('Ingestion health (daily digest)');
    });

    it('should show the message and since when the status lasts, from the context of the event, without the status change', async () => {
      const rendered = await safeRender(HEALTH_EMAIL_TEMPLATE, buildTemplateData([connectorEvent], DIGEST, eventData));
      expect(rendered).toContain('Last run failed: HTTP 401 Unauthorized');
      expect(rendered).not.toContain('&rarr;');
      expect(rendered).toContain('<i>Detected:</i> 28 Oct 2026, 06:14 UTC');
    });

    it('should show neither message, date nor status when the event has no context: the scope alone', async () => {
      const rendered = await safeRender(HEALTH_EMAIL_TEMPLATE, buildTemplateData([connectorEvent], DIGEST));
      expect(rendered).not.toContain('Detected');
      expect(rendered).not.toContain('<i>Status:</i>');
      expect(rendered).toContain('>Critical</span>');
    });

    it('should not show the sections of a live alert', async () => {
      const rendered = await safeRender(HEALTH_EMAIL_TEMPLATE, buildTemplateData([connectorEvent], DIGEST, eventData));
      expect(rendered).not.toContain('a recipient of the trigger');
      expect(rendered).not.toContain('View connector');
    });

    it('should link to every source that needs attention', async () => {
      const rendered = await safeRender(HEALTH_EMAIL_TEMPLATE, buildTemplateData([connectorEvent], DIGEST, eventData));
      expect(rendered).toContain('/dashboard/integrations/deployed?health=critical,degraded');
      expect(rendered).toContain('See all sources that need attention');
    });

    it('should show the context of each occurrence when a source fails twice in the period, not the one of its first failure', async () => {
      // critical -> recovered -> critical for the same feed: the content holds its two critical events, in the order of the data
      const events = [
        { operation: 'critical', changes: { critical_messages: ['Feed execution failed: HTTP 401'], status_since: '2026-10-28T06:14:00.000Z' } },
        { operation: 'recovered', changes: { status_since: '2026-10-28T09:00:00.000Z' } },
        { operation: 'critical', changes: { critical_messages: ['Feed execution failed: HTTP 500'], status_since: '2026-10-28T15:30:00.000Z' } },
      ];
      const templateData = sanitizeNotificationData({
        notification_content: [{ title: 'Abuse feed', events: events.map(({ operation }) => ({ operation, entity_type: 'IngestionCsv', instance_id: 'feed-id' })) }],
        notification: DIGEST,
        data: events.map(({ operation, changes }) => ({
          notification_id: 'trigger-id',
          type: operation,
          message: '',
          instance: { id: 'feed-id', entity_type: 'IngestionCsv', ingestion_health_changes: changes },
        })),
        settings: { platform_title: 'OpenCTI' },
        platform_uri: 'https://opencti.local',
      });
      const rendered = await safeRender(HEALTH_EMAIL_TEMPLATE, templateData);
      // Each critical line with its own error and detection date, in order
      const first = rendered.indexOf('HTTP 401');
      const second = rendered.indexOf('HTTP 500');
      expect(first).toBeGreaterThan(-1);
      expect(second).toBeGreaterThan(first);
      expect(rendered.indexOf('HTTP 401', first + 1)).toBe(-1);
      expect(rendered).toContain('28 Oct 2026, 06:14 UTC');
      expect(rendered).toContain('28 Oct 2026, 09:00 UTC');
      expect(rendered).toContain('28 Oct 2026, 15:30 UTC');
    });
  });
});
