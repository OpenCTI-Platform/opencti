import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { handleWebhookNotification } from '../../../src/manager/publisherManager';

describe('handleWebhookNotification', () => {
  const mockFetch = vi.fn();

  beforeEach(() => {
    vi.clearAllMocks();
    vi.stubGlobal('fetch', mockFetch);
  });

  afterEach(() => {
    vi.restoreAllMocks();
    vi.unstubAllGlobals();
  });

  // Helper to extract the call args from mocked fetch
  const getFetchCallArgs = () => {
    const [url, init] = mockFetch.mock.calls[0];
    const body = init?.body ? JSON.parse(init.body) : undefined;
    return { url, method: init?.method, headers: init?.headers, body };
  };

  // Helper to extract URL and params separately
  const getFetchUrlAndParams = () => {
    const [rawUrl] = mockFetch.mock.calls[0];
    const urlObj = new URL(rawUrl);
    const params: Record<string, string> = {};
    urlObj.searchParams.forEach((v, k) => {
      params[k] = v;
    });
    return { url: `${urlObj.origin}${urlObj.pathname}`, params };
  };

  it('should call fetch with the correct URL, method and body', async () => {
    const configurationString = JSON.stringify({
      url: 'https://my-webhook-endpoint.com/test',
      verb: 'POST',
      template: '{}',
    });
    mockFetch.mockResolvedValue(new Response(JSON.stringify({ status: 'ok' }), { status: 200 }));

    await handleWebhookNotification(configurationString, {});

    expect(mockFetch).toHaveBeenCalledOnce();
    const { url, method, body } = getFetchCallArgs();
    expect(url).toContain('https://my-webhook-endpoint.com/test');
    expect(method).toBe('POST');
    expect(body).toEqual({});
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

    mockFetch.mockResolvedValue(new Response(JSON.stringify({ status: 'ok' }), { status: 200 }));

    await handleWebhookNotification(configurationString, templateData);

    expect(mockFetch).toHaveBeenCalledTimes(1);

    const { headers } = getFetchCallArgs();
    expect(headers).toMatchObject({
      'Content-Type': 'application/json',
      'X-API-Key': 'filigran-secret-key-123',
      Accept: 'application/json',
    });

    const { url, params } = getFetchUrlAndParams();
    expect(url).toBe('https://api.filigran.io/v1/ingest');
    expect(params).toEqual({
      source: 'opencti-platform',
      type: 'notification',
    });

    const { body } = getFetchCallArgs();
    const expectedData = {
      message: 'Update on Stix-Object-Cyber-Tigrou by test-admin',
      source_id: 'trigger-id-abcde',
    };
    expect(body).toEqual(expectedData);
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

    mockFetch.mockResolvedValue(new Response(JSON.stringify({ status: 'ok' }), { status: 200 }));

    await handleWebhookNotification(configurationString, templateDataWithNewline);

    expect(mockFetch).toHaveBeenCalledOnce();

    const { body } = getFetchCallArgs();
    expect(body).toHaveProperty('description');
    expect(typeof body.description).toBe('string');
    expect(body.description).toContain('Line 1');
    expect(body.description).toContain('Line 2');
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

    mockFetch.mockResolvedValue(new Response(JSON.stringify({ status: 'ok' }), { status: 200 }));

    await handleWebhookNotification(configurationString, templateDataWithNesting);

    expect(mockFetch).toHaveBeenCalledOnce();

    const { body } = getFetchCallArgs();
    expect(body).toHaveProperty('title');
    expect(body).toHaveProperty('author_bio');
    expect(body).toHaveProperty('first_event_message');

    expect(body.title).toContain('Quarterly');
    expect(body.title).toContain('Report');
    expect(body.author_bio).toContain('Cybersecurity expert');
    expect(body.first_event_message).toContain('First alert');
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

    mockFetch.mockResolvedValue(new Response(JSON.stringify({ status: 'ok' }), { status: 200 }));

    await handleWebhookNotification(configurationString, templateDataWithSlash);

    expect(mockFetch).toHaveBeenCalledOnce();

    const { body } = getFetchCallArgs();
    expect(body).toHaveProperty('description');
    expect(body.description).toBe('This is a path: /home/user/file.txt');
  });
});
