import { describe, expect, it } from 'vitest';
import type { MemberAccessInput } from '../../../src/generated/graphql';
import { sanitizeAuthorizedMembers } from '../../../src/utils/authorizedMembers';

describe('sanitizeAuthorizedMembers tests', () => {
  it('member with no group restriction', () => {
    const input: MemberAccessInput[] = [{
      id: '66ac180d-aa8d-4566-ba51-8b385b6ec38e',
      access_right: 'admin',
    }];
    const sanitizedInput = sanitizeAuthorizedMembers(input);
    const expected = [{
      id: '66ac180d-aa8d-4566-ba51-8b385b6ec38e',
      access_right: 'admin',
    }];
    expect(sanitizedInput).toEqual(expected);
  });
  it('member with group restriction', () => {
    const input: MemberAccessInput[] = [{
      id: '66ac180d-aa8d-4566-ba51-8b385b6ec38e',
      access_right: 'view',
      groups_restriction_ids: ['1e522ce6-f324-4cc9-a2ab-a1a934a1c209']
    }];
    const sanitizedInput = sanitizeAuthorizedMembers(input);
    const expected = [{
      id: '66ac180d-aa8d-4566-ba51-8b385b6ec38e',
      access_right: 'view',
      groups_restriction_ids: ['1e522ce6-f324-4cc9-a2ab-a1a934a1c209']
    }];
    expect(sanitizedInput).toEqual(expected);
  });
  it('same member with different group restriction', () => {
    const input: MemberAccessInput[] = [{
      id: '66ac180d-aa8d-4566-ba51-8b385b6ec38e',
      access_right: 'view',
      groups_restriction_ids: ['2a522ce7-j325-4hc8-a2ab-t8a934a1c645']
    },
    {
      id: '66ac180d-aa8d-4566-ba51-8b385b6ec38e',
      access_right: 'view',
      groups_restriction_ids: ['1e522ce6-f324-4cc9-a2ab-a1a934a1c209']
    }];
    const sanitizedInput = sanitizeAuthorizedMembers(input);
    const expected = [{
      id: '66ac180d-aa8d-4566-ba51-8b385b6ec38e',
      access_right: 'view',
      groups_restriction_ids: ['2a522ce7-j325-4hc8-a2ab-t8a934a1c645']
    },
    {
      id: '66ac180d-aa8d-4566-ba51-8b385b6ec38e',
      access_right: 'view',
      groups_restriction_ids: ['1e522ce6-f324-4cc9-a2ab-a1a934a1c209']
    }];
    expect(sanitizedInput).toEqual(expected);
  });
  it('same member with same group restriction should not return duplicate', () => {
    const input: MemberAccessInput[] = [{
      id: '66ac180d-aa8d-4566-ba51-8b385b6ec38e',
      access_right: 'view',
      groups_restriction_ids: ['2a522ce7-j325-4hc8-a2ab-t8a934a1c645']
    },
    {
      id: '66ac180d-aa8d-4566-ba51-8b385b6ec38e',
      access_right: 'view',
      groups_restriction_ids: ['2a522ce7-j325-4hc8-a2ab-t8a934a1c645']
    }];
    const sanitizedInput = sanitizeAuthorizedMembers(input);
    const expected = [{
      id: '66ac180d-aa8d-4566-ba51-8b385b6ec38e',
      access_right: 'view',
      groups_restriction_ids: ['2a522ce7-j325-4hc8-a2ab-t8a934a1c645']
    }];
    expect(sanitizedInput).toEqual(expected);
  });
  it('same member with both a restricted and an unrestricted entry — both should be kept regardless of order', () => {
    const restricted: MemberAccessInput = {
      id: '66ac180d-aa8d-4566-ba51-8b385b6ec38e',
      access_right: 'edit',
      groups_restriction_ids: ['1e522ce6-f324-4cc9-a2ab-a1a934a1c209'],
    };
    const unrestricted: MemberAccessInput = {
      id: '66ac180d-aa8d-4566-ba51-8b385b6ec38e',
      access_right: 'view',
    };

    // restricted before unrestricted
    expect(sanitizeAuthorizedMembers([restricted, unrestricted])).toEqual([restricted, unrestricted]);
    // unrestricted before restricted
    expect(sanitizeAuthorizedMembers([unrestricted, restricted])).toEqual([unrestricted, restricted]);
  });
  it('same member with two unrestricted entries — only the first should be kept', () => {
    const input: MemberAccessInput[] = [
      { id: '66ac180d-aa8d-4566-ba51-8b385b6ec38e', access_right: 'view' },
      { id: '66ac180d-aa8d-4566-ba51-8b385b6ec38e', access_right: 'admin' },
    ];
    const sanitizedInput = sanitizeAuthorizedMembers(input);
    expect(sanitizedInput).toEqual([{ id: '66ac180d-aa8d-4566-ba51-8b385b6ec38e', access_right: 'view' }]);
  });
});
