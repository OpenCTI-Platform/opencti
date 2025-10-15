import { describe, expect, it } from 'vitest';
import axios from 'axios';
import { getBaseUrl } from '../../src/config/conf';

describe('Should /health be available', () => {
  it('Should /health be available', async () => {
    // Check that url config is fine.
    const axiosHealthResponse = await axios.get(`${getBaseUrl()}/health?health_access_key=cihealthkey`);
    expect(axiosHealthResponse.status, '200');
  });
});
