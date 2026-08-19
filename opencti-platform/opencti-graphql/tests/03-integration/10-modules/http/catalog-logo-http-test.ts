import { describe, expect, it } from 'vitest';
import { API_URI, generateBasicAuth } from '../../../utils/testQuery';
import { basePath } from '../../../../src/config/conf';
import { rawUpload } from '../../../../src/database/raw-file-storage';

const CATALOG_LOGO_PATH = `${API_URI}${basePath}/catalog/logo`;

describe('catalog logo HTTP integration', () => {
  it('should return 403 when unauthenticated', async () => {
    const res = await fetch(`${CATALOG_LOGO_PATH}/does-not-matter.png`);
    expect(res.status).toBe(403);
  });

  it('should return 404 when authenticated but file does not exist', async () => {
    const res = await fetch(`${CATALOG_LOGO_PATH}/missing-logo.png`, {
      headers: {
        authorization: generateBasicAuth(),
      },
    });
    expect(res.status).toBe(404);
  });

  it('should return 200 and content-type when logo exists', async () => {
    await rawUpload('catalog-logos/integration-logo.png', Buffer.from('png-content'));
    const res = await fetch(`${CATALOG_LOGO_PATH}/integration-logo.png`, {
      headers: {
        authorization: generateBasicAuth(),
      },
    });
    expect(res.status).toBe(200);
    expect(res.headers.get('content-type')).toContain('image/png');
  });
});
