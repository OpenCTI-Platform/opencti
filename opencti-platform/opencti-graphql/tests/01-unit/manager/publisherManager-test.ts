import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import ejs from 'ejs';
import axios, { type AxiosInstance } from 'axios';
import { handleWebhookNotification } from '../../../src/manager/publisherManager';

describe('handleWebhookNotification', () => {
  const mockedAxiosInstance = vi.fn();
  beforeEach(() => {
    vi.spyOn(axios, 'create').mockReturnValue(mockedAxiosInstance as unknown as AxiosInstance);
    vi.spyOn(ejs, 'render'); // We are only spying on `render` without changing its initial behavior for now
  });
  afterEach(() => {
    vi.restoreAllMocks();
  });

  it('should intercept the axios.create call and use a mock instance', async () => {
    const configurationString = JSON.stringify({ url: 'https://my-webhook-endpoint.com/test', verb: 'POST', template: '{}' });
    mockedAxiosInstance.mockResolvedValue({ status: 200, data: 'success from spy' });
    await handleWebhookNotification(configurationString, {});
    expect(axios.create).toHaveBeenCalledTimes(1);
    expect(mockedAxiosInstance).toHaveBeenCalledOnce();
    const axiosCallArgs = mockedAxiosInstance.mock.calls[0][0];
    expect(axiosCallArgs.url).toBe('https://my-webhook-endpoint.com/test');
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
      // Add more data to mimic reality
      settings: {},
      data: [],
    };
    const renderedTemplatePayload = '{ "message": "Update on Stix-Object-Cyber-Tigrou by test-admin", "source_id": "trigger-id-abcde" }';
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
    expect(axiosCallArgs.data).toEqual(JSON.parse(renderedTemplatePayload));
  });

  it('should correctly escape newline characters in template data', async () => {
    const webhookConfiguration = {
      url: 'https://api.filigran.io/v1/ingest',
      verb: 'POST',
      template: '{ "description": "<%= description %>" }',
    };
    const configurationString = JSON.stringify(webhookConfiguration);
    const templateDataWithNewline = {
      description: 'Line 1\nLine 2'
    };
    const renderedTemplate = JSON.stringify({ description: 'Line 1\nLine 2' });
    vi.mocked(ejs.render).mockReturnValue(renderedTemplate);
    mockedAxiosInstance.mockResolvedValue({ status: 200 });
    await handleWebhookNotification(configurationString, templateDataWithNewline);
    expect(ejs.render).toHaveBeenCalledOnce();
    expect(ejs.render).toHaveBeenCalledWith(
      webhookConfiguration.template,
      templateDataWithNewline,
      expect.objectContaining({
        escape: expect.any(Function)
      })
    );
    expect(mockedAxiosInstance).toHaveBeenCalledOnce();
    expect(mockedAxiosInstance).toHaveBeenCalledWith(expect.objectContaining({
      data: JSON.parse(renderedTemplate),
    }));
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
          bio: 'Cybersecurity expert.\nAuthor of several publications.'
        },
        events: [
          { id: 'evt-1', message: 'First alert:\nsuspicious connection.' },
          { id: 'evt-2', message: 'Second alert, no line break.' }
        ],
        tags: ['urgent', 'review\nneeded'],
        is_published: true,
        version: 2,
      }
    };
    const renderedTemplate = JSON.stringify({
      title: 'Quarterly\nReport',
      author_bio: 'Cybersecurity expert.\nAuthor of several publications.',
      first_event_message: 'First alert:\nsuspicious connection.'
    });
    vi.mocked(ejs.render).mockReturnValue(renderedTemplate);
    mockedAxiosInstance.mockResolvedValue({ status: 200 });
    await handleWebhookNotification(configurationString, templateDataWithNesting);
    expect(ejs.render).toHaveBeenCalledOnce();
    expect(ejs.render).toHaveBeenCalledWith(
      webhookConfiguration.template,
      templateDataWithNesting,
      expect.objectContaining({
        escape: expect.any(Function)
      })
    );
    expect(mockedAxiosInstance).toHaveBeenCalledOnce();
    const axiosCallArgs = mockedAxiosInstance.mock.calls[0][0];
    expect(axiosCallArgs.data).toEqual(JSON.parse(renderedTemplate));
  });

  it('should correctly escape forward slashes in template data', async () => {
    const webhookConfiguration = {
      url: 'https://api.filigran.io/v1/ingest',
      verb: 'POST',
      template: '{ "description": "<%= description %>" }',
    };
    const configurationString = JSON.stringify(webhookConfiguration);
    const templateDataWithSlash = {
      description: 'This is a path: /home/user/file.txt'
    };
    const renderedTemplate = JSON.stringify({ description: 'This is a path: /home/user/file.txt' });
    vi.mocked(ejs.render).mockReturnValue(renderedTemplate);
    mockedAxiosInstance.mockResolvedValue({ status: 200 });
    await handleWebhookNotification(configurationString, templateDataWithSlash);
    expect(ejs.render).toHaveBeenCalledOnce();
    expect(ejs.render).toHaveBeenCalledWith(
      webhookConfiguration.template,
      templateDataWithSlash,
      expect.objectContaining({
        escape: expect.any(Function)
      })
    );
    expect(mockedAxiosInstance).toHaveBeenCalledOnce();
    expect(mockedAxiosInstance).toHaveBeenCalledWith(expect.objectContaining({
      data: JSON.parse(renderedTemplate),
    }));
  });
});
