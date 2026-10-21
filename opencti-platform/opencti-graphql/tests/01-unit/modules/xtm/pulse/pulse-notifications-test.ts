import { describe, expect, it } from 'vitest';
import { pulsePlatformsBucketText } from '../../../../../src/modules/xtm/pulse/pulse-notifications';

describe('Threat Pulse trending notifications', () => {
  it('should word the platform buckets of XTM Hub', () => {
    expect(pulsePlatformsBucketText('<5')).toBe('fewer than 5 platforms');
    expect(pulsePlatformsBucketText('25-49')).toBe('25 to 49 platforms');
    expect(pulsePlatformsBucketText('250+')).toBe('250 platforms or more');
  });

  it('should word nothing for a missing or unknown bucket', () => {
    expect(pulsePlatformsBucketText(null)).toBeNull();
    expect(pulsePlatformsBucketText(undefined)).toBeNull();
    expect(pulsePlatformsBucketText('many')).toBeNull();
  });
});
