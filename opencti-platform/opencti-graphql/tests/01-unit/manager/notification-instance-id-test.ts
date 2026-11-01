import { describe, expect, it } from 'vitest';
import { resolveNotificationInstanceId } from '../../../src/manager/notification-instance-id';
import { STIX_EXT_OCTI } from '../../../src/types/stix-2-1-extensions';

const INTERNAL_ID = '6a1c3f6e-3c1b-4a8e-9f3d-5b1f0a2c7d10';
const STANDARD_ID = 'incident--0a6f5d3e-8f2b-5c4d-9e1a-7b3c2d1e0f9a';

describe('resolveNotificationInstanceId', () => {
  it('uses the internal id of a STIX instance, not its standard id', () => {
    const instance = { id: STANDARD_ID, extensions: { [STIX_EXT_OCTI]: { id: INTERNAL_ID } } };
    expect(resolveNotificationInstanceId(instance)).toBe(INTERNAL_ID);
  });

  it('keeps the same id after a rename regenerates the standard id', () => {
    const before = { id: STANDARD_ID, extensions: { [STIX_EXT_OCTI]: { id: INTERNAL_ID } } };
    const after = { id: 'incident--1b7e6f4a-9a3c-5d5e-8f2b-8c4d3e2f1a0b', extensions: { [STIX_EXT_OCTI]: { id: INTERNAL_ID } } };
    expect(resolveNotificationInstanceId(after)).toBe(resolveNotificationInstanceId(before));
  });

  it('falls back to id for an instance without the OpenCTI extension (activity events)', () => {
    expect(resolveNotificationInstanceId({ id: INTERNAL_ID })).toBe(INTERNAL_ID);
    expect(resolveNotificationInstanceId({ id: STANDARD_ID, extensions: {} })).toBe(STANDARD_ID);
    expect(resolveNotificationInstanceId({ id: STANDARD_ID, extensions: { [STIX_EXT_OCTI]: {} } })).toBe(STANDARD_ID);
  });

  it('returns a missing id as is', () => {
    expect(resolveNotificationInstanceId({})).toBeUndefined();
    expect(resolveNotificationInstanceId({ id: null })).toBeNull();
  });
});
