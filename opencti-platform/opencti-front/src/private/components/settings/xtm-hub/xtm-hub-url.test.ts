import { describe, expect, it } from 'vitest';
import { buildXtmHubRegistrationUrl } from './xtm-hub-url';

const PLATFORM_ID = '2295d0ae-6438-4012-9791-6cc66afa354d';

describe('buildXtmHubRegistrationUrl', () => {
  it.each([
    ['https://hub.filigran.io'],
    ['https://hub.filigran.io/'],
  ])('links to the hub redirect resolving the registration of the platform with the hub url %s', (hubUrl) => {
    expect(buildXtmHubRegistrationUrl(hubUrl, PLATFORM_ID))
      .toBe(`https://hub.filigran.io/redirect/opencti-registration?platform_id=${PLATFORM_ID}`);
  });

  it.each([[undefined], [null], ['']])('falls back to the hub when the platform id is %s', (platformId) => {
    expect(buildXtmHubRegistrationUrl('https://hub.filigran.io', platformId)).toBe('https://hub.filigran.io');
  });
});
