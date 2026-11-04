import { describe, it, expect, vi, beforeEach } from 'vitest';
import { getHttpClient } from '../../../src/utils/http-client';
import { handleWebhookNotification, processNotificationData, resolveNotificationDataMarkings } from '../../../src/manager/publisherManager';
import { buildActivityNotificationData } from '../../../src/manager/activityManager';
import type { NotificationData } from '../../../src/utils/publisher-mock';
import type { StoreMarkingDefinition } from '../../../src/types/store';
import type { AuthUser } from '../../../src/types/user';
import { BYPASS } from '../../../src/utils/access';
import { sanitizeNotificationData } from '../../../src/utils/templateContextSanitizer';
import { safeRender } from '../../../src/utils/safeEjs';

const { mockedCall } = vi.hoisted(() => ({ mockedCall: vi.fn() }));
vi.mock('../../../src/utils/http-client', async (importOriginal) => ({
  ...(await importOriginal<typeof import('../../../src/utils/http-client')>()),
  getHttpClient: vi.fn(() => ({ call: mockedCall })),
}));

describe('handleWebhookNotification', () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  it('should send the webhook through the http client', async () => {
    const configurationString = JSON.stringify({
      url: 'https://my-webhook-endpoint.com/test',
      verb: 'POST',
      template: '{}',
    });
    mockedCall.mockResolvedValue({ status: 200, data: 'success from spy' });

    await handleWebhookNotification(configurationString, {});

    expect(getHttpClient).toHaveBeenCalledTimes(1);
    expect(mockedCall).toHaveBeenCalledOnce();
    const callArgs = mockedCall.mock.calls[0][0];
    expect(callArgs.url).toBe('https://my-webhook-endpoint.com/test');
    expect(callArgs.method).toBe('POST');
    expect(callArgs.data).toEqual({});
  });

  it('should normalize header names and values copied from a curl command', async () => {
    const configurationString = JSON.stringify({
      url: 'https://my-webhook-endpoint.com/test',
      verb: 'POST',
      template: '{}',
      headers: [
        { attribute: 'Authorization: ', value: 'Bearer token\n' },
        { attribute: ' X-API-Key', value: 'key' },
        { attribute: ':', value: 'dropped' },
      ],
    });
    mockedAxiosInstance.mockResolvedValue({ status: 200, data: 'success' });

    await handleWebhookNotification(configurationString, {});

    expect(axios.create).toHaveBeenCalledWith(expect.objectContaining({
      headers: { Authorization: 'Bearer token', 'X-API-Key': 'key' },
    }));
  });

  it('should send the DELETE verb of a notifier saved with a leading space', async () => {
    const configurationString = JSON.stringify({
      url: 'https://my-webhook-endpoint.com/test',
      verb: ' DELETE',
      template: '{}',
    });
    mockedAxiosInstance.mockResolvedValue({ status: 200, data: 'success' });

    await handleWebhookNotification(configurationString, {});

    expect(mockedAxiosInstance.mock.calls[0][0].method).toBe('DELETE');
  });

  it('should call webhook with correct POST payload, headers, and params', async () => {
    const webhookConfiguration = {
      url: 'https://api.filigran.io/v1/ingest',
      verb: 'POST',
      template: '{ "message": "Update on <%= content[0].title %> by <%= user.user_name %>", "source_id": "<%= notification.id %>" }',
      headers: [
        { attribute: 'Content-Type', value: 'application/json' },
        { attribute: 'X-API-Key', value: 'filigran-secret-key-123' },
        { attribute: 'Accept', value: 'application/json' },
      ],
      params: [
        { attribute: 'source', value: 'opencti-platform' },
        { attribute: 'type', value: 'notification' },
      ],
    };
    const configurationString = JSON.stringify(webhookConfiguration);
    const templateData = {
      content: [{ title: 'Stix-Object-Cyber-Tigrou' }],
      user: { user_name: 'test-admin' },
      notification: { id: 'trigger-id-abcde' },
      settings: {},
      data: [],
    };

    mockedCall.mockResolvedValue({ status: 200, data: 'OK' });

    await handleWebhookNotification(configurationString, templateData);

    expect(getHttpClient).toHaveBeenCalledTimes(1);
    expect(getHttpClient).toHaveBeenCalledWith(expect.objectContaining({
      headers: {
        'Content-Type': 'application/json',
        'X-API-Key': 'filigran-secret-key-123',
        Accept: 'application/json',
      },
    }));
    expect(mockedCall).toHaveBeenCalledTimes(1);

    const callArgs = mockedCall.mock.calls[0][0];
    expect(callArgs.url).toBe(webhookConfiguration.url);
    expect(callArgs.method).toBe('POST');
    expect(callArgs.params).toEqual({
      source: 'opencti-platform',
      type: 'notification',
    });

    // Verify that the template has been rendered with expected data
    const expectedData = {
      message: 'Update on Stix-Object-Cyber-Tigrou by test-admin',
      source_id: 'trigger-id-abcde',
    };
    expect(callArgs.data).toEqual(expectedData);
  });

  it('should correctly escape newline characters in template data', async () => {
    const webhookConfiguration = {
      url: 'https://api.filigran.io/v1/ingest',
      verb: 'POST',
      template: '{ "description": "<%= description %>" }',
    };
    const configurationString = JSON.stringify(webhookConfiguration);
    const templateDataWithNewline = {
      description: 'Line 1\nLine 2',
    };

    mockedCall.mockResolvedValue({ status: 200 });

    await handleWebhookNotification(configurationString, templateDataWithNewline);

    expect(mockedCall).toHaveBeenCalledOnce();

    const callArgs = mockedCall.mock.calls[0][0];
    // Ensure the template rendering produce valid JSON
    expect(callArgs.data).toHaveProperty('description');
    expect(typeof callArgs.data.description).toBe('string');
    expect(callArgs.data.description).toContain('Line 1');
    expect(callArgs.data.description).toContain('Line 2');
  });

  it('should escape line breaks in nested objects and arrays', async () => {
    const webhookConfiguration = {
      url: 'https://api.filigran.io/v1/ingest',
      verb: 'POST',
      template: '{ "title": "<%= report.title %>", "author_bio": "<%= report.author.bio %>", "first_event_message": "<%= report.events[0].message %>" }',
    };
    const configurationString = JSON.stringify(webhookConfiguration);
    const templateDataWithNesting = {
      report: {
        title: 'Quarterly\nReport',
        author: {
          name: 'John Doe',
          bio: 'Cybersecurity expert.\nAuthor of several publications.',
        },
        events: [
          { id: 'evt-1', message: 'First alert:\nsuspicious connection.' },
          { id: 'evt-2', message: 'Second alert, no line break.' },
        ],
        tags: ['urgent', 'review\nneeded'],
        is_published: true,
        version: 2,
      },
    };

    mockedCall.mockResolvedValue({ status: 200 });

    await handleWebhookNotification(configurationString, templateDataWithNesting);

    expect(mockedCall).toHaveBeenCalledOnce();

    const callArgs = mockedCall.mock.calls[0][0];
    // Check imbricated properties are correctly rendered
    expect(callArgs.data).toHaveProperty('title');
    expect(callArgs.data).toHaveProperty('author_bio');
    expect(callArgs.data).toHaveProperty('first_event_message');

    // Ensure new lines are correctly rendered
    expect(callArgs.data.title).toContain('Quarterly');
    expect(callArgs.data.title).toContain('Report');
    expect(callArgs.data.author_bio).toContain('Cybersecurity expert');
    expect(callArgs.data.first_event_message).toContain('First alert');
  });

  it('should set a request timeout on the webhook http client to prevent indefinite hangs', async () => {
    const configurationString = JSON.stringify({
      url: 'https://my-webhook-endpoint.com/test',
      verb: 'POST',
      template: '{}',
    });
    mockedCall.mockResolvedValue({ status: 200, data: 'success' });

    await handleWebhookNotification(configurationString, {});

    expect(getHttpClient).toHaveBeenCalledWith(expect.objectContaining({ timeout: 300_000 }));
    const clientOptions = vi.mocked(getHttpClient).mock.calls[0][0];
    // A falsy timeout (0/undefined) means the http client waits forever; guard against ever regressing to that.
    expect(clientOptions.timeout).toBeTypeOf('number');
    expect(clientOptions.timeout).toBeGreaterThan(0);
  });

  it('should correctly handle forward slashes in template data', async () => {
    const webhookConfiguration = {
      url: 'https://api.filigran.io/v1/ingest',
      verb: 'POST',
      template: '{ "description": "<%= description %>" }',
    };
    const configurationString = JSON.stringify(webhookConfiguration);
    const templateDataWithSlash = {
      description: 'This is a path: /home/user/file.txt',
    };

    mockedCall.mockResolvedValue({ status: 200 });

    await handleWebhookNotification(configurationString, templateDataWithSlash);

    expect(mockedCall).toHaveBeenCalledOnce();

    const callArgs = mockedCall.mock.calls[0][0];
    expect(callArgs.data).toHaveProperty('description');
    expect(callArgs.data.description).toBe('This is a path: /home/user/file.txt');
  });
});

describe('resolveNotificationDataMarkings', () => {
  const tlpAmber = {
    id: 'tlp-amber-internal-id',
    internal_id: 'tlp-amber-internal-id',
    standard_id: 'marking-definition--f88d31f6-486f-44da-b317-01333bde0b82',
    definition_type: 'TLP',
    definition: 'TLP:AMBER',
    x_opencti_color: '#ffc000',
    x_opencti_order: 3,
    entity_type: 'Marking-Definition',
  } as unknown as StoreMarkingDefinition;
  const tlpRed = {
    id: 'tlp-red-internal-id',
    internal_id: 'tlp-red-internal-id',
    standard_id: 'marking-definition--5e57c739-391a-4eb3-b6be-7d15ca92d5ed',
    definition_type: 'TLP',
    definition: 'TLP:RED',
    x_opencti_color: '#c62828',
    x_opencti_order: 4,
    entity_type: 'Marking-Definition',
  } as unknown as StoreMarkingDefinition;
  const markingsMap = new Map<string, StoreMarkingDefinition>([
    [tlpAmber.id, tlpAmber],
    [tlpAmber.standard_id, tlpAmber],
    [tlpRed.id, tlpRed],
    [tlpRed.standard_id, tlpRed],
  ]);
  const amberUser = { id: 'amber-user', capabilities: [], allowed_marking: [tlpAmber] } as unknown as AuthUser;
  const bypassUser = { id: 'bypass-user', capabilities: [{ name: BYPASS }], allowed_marking: [] } as unknown as AuthUser;
  const buildData = (instance: Record<string, unknown>): NotificationData[] => [{
    notification_id: 'trigger-id',
    instance: instance as NotificationData['instance'],
    type: 'create',
    message: '[report] My report',
  }];

  it('should expose the resolved markings of the instance as objectMarking', () => {
    const data = buildData({ id: 'report--1', name: 'My report', object_marking_refs: [tlpAmber.standard_id] });

    const [resolved] = resolveNotificationDataMarkings(data, markingsMap, amberUser);

    expect((resolved.instance as any).objectMarking).toEqual([{
      id: tlpAmber.id,
      standard_id: tlpAmber.standard_id,
      definition_type: 'TLP',
      definition: 'TLP:AMBER',
      x_opencti_color: '#ffc000',
      x_opencti_order: 3,
    }]);
  });

  it('should ignore unknown marking refs and instances without markings', () => {
    const data = [
      ...buildData({ id: 'report--1', object_marking_refs: ['marking-definition--unknown'] }),
      ...buildData({ id: 'report--2' }),
    ];

    const resolved = resolveNotificationDataMarkings(data, markingsMap, amberUser);

    expect((resolved[0].instance as any).objectMarking).toEqual([]);
    expect((resolved[1].instance as any).objectMarking).toEqual([]);
  });

  it('should not resolve the markings the recipient is not allowed to see', () => {
    // ex: TLP:RED was just added, the user lost access to the report and is notified of its removal
    const data = buildData({ id: 'report--1', object_marking_refs: [tlpAmber.standard_id, tlpRed.standard_id] });

    const [resolved] = resolveNotificationDataMarkings(data, markingsMap, amberUser);

    expect((resolved.instance as any).objectMarking.map((m: StoreMarkingDefinition) => m.definition)).toEqual(['TLP:AMBER']);
  });

  it('should resolve all the markings for a user with the BYPASS capability', () => {
    const data = buildData({ id: 'report--1', object_marking_refs: [tlpAmber.standard_id, tlpRed.standard_id] });

    const [resolved] = resolveNotificationDataMarkings(data, markingsMap, bypassUser);

    expect((resolved.instance as any).objectMarking.map((m: StoreMarkingDefinition) => m.definition)).toEqual(['TLP:AMBER', 'TLP:RED']);
  });

  it('should not resolve any marking when the recipient is unknown', () => {
    const data = buildData({ id: 'report--1', object_marking_refs: [tlpAmber.standard_id] });

    const [resolved] = resolveNotificationDataMarkings(data, markingsMap, undefined);

    expect((resolved.instance as any).objectMarking).toEqual([]);
  });

  it('should not mutate the original instance', () => {
    const instance = { id: 'report--1', object_marking_refs: [tlpAmber.standard_id] };

    resolveNotificationDataMarkings(buildData(instance), markingsMap, amberUser);

    expect(instance).not.toHaveProperty('objectMarking');
  });

  it('should make the markings available in a custom email template', async () => {
    const data = resolveNotificationDataMarkings(
      buildData({ id: 'report--1', object_marking_refs: [tlpAmber.standard_id] }),
      markingsMap,
      amberUser,
    );
    const template = '<% data[0].instance.objectMarking.forEach(function(marking) { %><%= marking.definition %><% }) %>';

    const rendered = await safeRender(template, sanitizeNotificationData({ data }));

    expect(rendered).toBe('TLP:AMBER');
  });
});

describe('processNotificationData', () => {
  const NOTIFICATION_ID = 'trigger-id';
  const user = { user_id: 'user-id' } as any;
  const notificationMap = new Map([[NOTIFICATION_ID, { id: NOTIFICATION_ID }]] as any);
  const usersMap = new Map([['user-id', { id: 'user-id' }]] as any);

  // The activity events title their notification with the element name, such as an ingestion name: any name is possible
  it.each(['constructor', 'toString', 'hasOwnProperty', '__proto__'])('should group the events of an element named %s under its name', async (name) => {
    const instance = buildActivityNotificationData({ id: 'ingestion-id', entity_type: 'IngestionRss', entity_name: name } as any);
    const data = [1, 2].map((index) => ({ notification_id: NOTIFICATION_ID, instance, type: 'action', message: `message ${index}` }));

    const content = await processNotificationData({} as any, notificationMap as any, user, data as any, usersMap as any);

    expect(Object.entries(content)).toEqual([[name, [
      { operation: 'action', message: 'message 1', instance_id: 'ingestion-id', entity_type: 'IngestionRss' },
      { operation: 'action', message: 'message 2', instance_id: 'ingestion-id', entity_type: 'IngestionRss' },
    ]]]);
  });
});
