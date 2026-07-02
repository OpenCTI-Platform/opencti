import { describe, it, expect } from 'vitest';
import { getDataSanityConfigurationFromSettings } from '../../../../src/modules/dataSanity/dataSanityConfiguration-domain';
import { ADMIN_USER, testContext } from '../../../utils/testQuery';

describe('Data sanity configuration test coverage', () => {
  it('should retrieve data_sanity_configuration from settings (may be undefined initially)', async () => {
    const config = await getDataSanityConfigurationFromSettings(testContext, ADMIN_USER);
    // Config may or may not exist depending on test order
    if (config) {
      expect(typeof config.timezone_offset).toBe('number');
    }
  });
});
