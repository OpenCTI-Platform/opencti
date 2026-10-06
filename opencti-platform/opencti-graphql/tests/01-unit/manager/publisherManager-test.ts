import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import axios, { type AxiosInstance } from 'axios';
import { handleWebhookNotification, resolveNotificationDataMarkings } from '../../../src/manager/publisherManager';
import type { NotificationData } from '../../../src/utils/publisher-mock';
import type { StoreMarkingDefinition } from '../../../src/types/store';
import type { AuthUser } from '../../../src/types/user';
import { BYPASS } from '../../../src/utils/access';
import { sanitizeNotificationData } from '../../../src/utils/templateContextSanitizer';
import { safeRender } from '../../../src/utils/safeEjs';

describe('handleWebhookNotification', () => {
  const mockedAxiosInstance = vi.fn();

  beforeEach(() => {
    vi.clearAllMocks();
    vi.spyOn(axios, 'create').mockReturnValue(mockedAxiosInstance as unknown as AxiosInstance);
  });

  afterEach(() => {
    vi.restoreAllMocks();
  });

  it('should intercept the axios.create call and use a mock instance', async () => {
    const configurationString = JSON.stringify({
      url: 'https://my-webhook-endpoint.com/test',
      verb: 'POST',
      template: '{}',
    });
    mockedAxiosInstance.mockResolvedValue({ status: 200, data: 'success from spy' });

    await handleWebhookNotification(configurationString, {});

    expect(axios.create).toHaveBeenCalledTimes(1);
    expect(mockedAxiosInstance).toHaveBeenCalledOnce();
    const axiosCallArgs = mockedAxiosInstance.mock.calls[0][0];
    expect(axiosCallArgs.url).toBe('https://my-webhook-endpoint.com/test');
    expect(axiosCallArgs.method).toBe('POST');
    expect(axiosCallArgs.data).toEqual({});
  });

  it('should normalize header names copied with a trailing colon', async () => {
    const configurationString = JSON.stringify({
      url: 'https://my-webhook-endpoint.com/test',
      verb: 'POST',
      template: '{}',
      headers: [
        { attribute: 'Authorization: ', value: 'Bearer token' },
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

    mockedAxiosInstance.mockResolvedValue({ status: 200, data: 'OK' });

    await handleWebhookNotification(configurationString, templateData);

    expect(axios.create).toHaveBeenCalledTimes(1);
    expect(axios.create).toHaveBeenCalledWith(expect.objectContaining({
      headers: {
        'Content-Type': 'application/json',
        'X-API-Key': 'filigran-secret-key-123',
        Accept: 'application/json',
      },
    }));
    expect(mockedAxiosInstance).toHaveBeenCalledTimes(1);

    const axiosCallArgs = mockedAxiosInstance.mock.calls[0][0];
    expect(axiosCallArgs.url).toBe(webhookConfiguration.url);
    expect(axiosCallArgs.method).toBe('POST');
    expect(axiosCallArgs.params).toEqual({
      source: 'opencti-platform',
      type: 'notification',
    });

    // Verify that the template has been rendered with expected data
    const expectedData = {
      message: 'Update on Stix-Object-Cyber-Tigrou by test-admin',
      source_id: 'trigger-id-abcde',
    };
    expect(axiosCallArgs.data).toEqual(expectedData);
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

    mockedAxiosInstance.mockResolvedValue({ status: 200 });

    await handleWebhookNotification(configurationString, templateDataWithNewline);

    expect(mockedAxiosInstance).toHaveBeenCalledOnce();

    const axiosCallArgs = mockedAxiosInstance.mock.calls[0][0];
    // Ensure the template rendering produce valid JSON
    expect(axiosCallArgs.data).toHaveProperty('description');
    expect(typeof axiosCallArgs.data.description).toBe('string');
    expect(axiosCallArgs.data.description).toContain('Line 1');
    expect(axiosCallArgs.data.description).toContain('Line 2');
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

    mockedAxiosInstance.mockResolvedValue({ status: 200 });

    await handleWebhookNotification(configurationString, templateDataWithNesting);

    expect(mockedAxiosInstance).toHaveBeenCalledOnce();

    const axiosCallArgs = mockedAxiosInstance.mock.calls[0][0];
    // Check imbricated properties are correctly rendered
    expect(axiosCallArgs.data).toHaveProperty('title');
    expect(axiosCallArgs.data).toHaveProperty('author_bio');
    expect(axiosCallArgs.data).toHaveProperty('first_event_message');

    // Ensure new lines are correctly rendered
    expect(axiosCallArgs.data.title).toContain('Quarterly');
    expect(axiosCallArgs.data.title).toContain('Report');
    expect(axiosCallArgs.data.author_bio).toContain('Cybersecurity expert');
    expect(axiosCallArgs.data.first_event_message).toContain('First alert');
  });

  it('should set a request timeout on the webhook http client to prevent indefinite hangs', async () => {
    const configurationString = JSON.stringify({
      url: 'https://my-webhook-endpoint.com/test',
      verb: 'POST',
      template: '{}',
    });
    mockedAxiosInstance.mockResolvedValue({ status: 200, data: 'success' });

    await handleWebhookNotification(configurationString, {});

    expect(axios.create).toHaveBeenCalledWith(expect.objectContaining({ timeout: 300_000 }));
    const axiosCreateArgs = (axios.create as unknown as ReturnType<typeof vi.fn>).mock.calls[0][0];
    // A falsy timeout (0/undefined) means axios waits forever; guard against ever regressing to that.
    expect(axiosCreateArgs.timeout).toBeTypeOf('number');
    expect(axiosCreateArgs.timeout).toBeGreaterThan(0);
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

    mockedAxiosInstance.mockResolvedValue({ status: 200 });

    await handleWebhookNotification(configurationString, templateDataWithSlash);

    expect(mockedAxiosInstance).toHaveBeenCalledOnce();

    const axiosCallArgs = mockedAxiosInstance.mock.calls[0][0];
    expect(axiosCallArgs.data).toHaveProperty('description');
    expect(axiosCallArgs.data.description).toBe('This is a path: /home/user/file.txt');
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
