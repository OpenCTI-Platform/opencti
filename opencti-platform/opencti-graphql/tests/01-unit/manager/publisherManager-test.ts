import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import axios, { type AxiosInstance } from 'axios';
import { handleWebhookNotification } from '../../../src/manager/publisherManager';

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
      template: '{}' 
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
      source_id: 'trigger-id-abcde' 
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
      description: 'Line 1\nLine 2'
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

  it('should correctly handle forward slashes in template data', async () => {
    const webhookConfiguration = {
      url: 'https://api.filigran.io/v1/ingest',
      verb: 'POST',
      template: '{ "description": "<%= description %>" }',
    };
    const configurationString = JSON.stringify(webhookConfiguration);
    const templateDataWithSlash = {
      description: 'This is a path: /home/user/file.txt'
    };
    
    mockedAxiosInstance.mockResolvedValue({ status: 200 });
    
    await handleWebhookNotification(configurationString, templateDataWithSlash);
    
    expect(mockedAxiosInstance).toHaveBeenCalledOnce();
    
    const axiosCallArgs = mockedAxiosInstance.mock.calls[0][0];
    expect(axiosCallArgs.data).toHaveProperty('description');
    expect(axiosCallArgs.data.description).toBe('This is a path: /home/user/file.txt');
  });
});
