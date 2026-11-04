import { describe, expect, it } from 'vitest';
import { sanitizeStreamEventOrigin } from '../../../src/database/stream/stream-utils';
import { EVENT_TYPE_DEPENDENCIES, EVENT_TYPE_INIT } from '../../../src/database/utils';

describe('Stream event origin', () => {
  it('should only keep the published origin attributes', () => {
    const origin = {
      socket: 'query',
      ip: 'value',
      user_id: 'user-1',
      group_ids: ['group-1'],
      organization_ids: ['organization-1'],
      user_metadata: { key: 'value' },
      referer: 'value',
      applicant_id: 'applicant-1',
      playbook_id: 'playbook-1',
      call_retry_number: 2,
      real_authentication_id: 'user-2',
      synchronized_upsert: true,
    };
    expect(sanitizeStreamEventOrigin(origin)).toEqual({
      socket: 'query',
      user_id: 'user-1',
      group_ids: ['group-1'],
      organization_ids: ['organization-1'],
      applicant_id: 'applicant-1',
      playbook_id: 'playbook-1',
    });
  });

  it('should not mutate the given origin', () => {
    const origin = { socket: 'query', referer: 'value', user_id: 'user-1' };
    sanitizeStreamEventOrigin(origin);
    expect(origin).toEqual({ socket: 'query', referer: 'value', user_id: 'user-1' });
  });

  it('should keep the referers of stream generated events', () => {
    expect(sanitizeStreamEventOrigin({ referer: EVENT_TYPE_DEPENDENCIES })).toEqual({ referer: EVENT_TYPE_DEPENDENCIES });
    expect(sanitizeStreamEventOrigin({ referer: EVENT_TYPE_INIT })).toEqual({ referer: EVENT_TYPE_INIT });
  });

  it('should handle missing origin', () => {
    expect(sanitizeStreamEventOrigin(undefined)).toBeUndefined();
    expect(sanitizeStreamEventOrigin({})).toEqual({});
  });
});
