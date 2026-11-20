import { describe, expect, it } from 'vitest';
import { buildIngestionErrorMeta } from '../../../src/manager/ingestionManager/ingestionManagerUtils';
import { HttpClientError } from '../../../src/utils/http-client';
import { INTERNAL_DESTINATION_ERROR_CODE } from '../../../src/utils/internal-destination';

describe('buildIngestionErrorMeta', () => {
  it('should keep only the code of an HTTP client error', () => {
    expect(buildIngestionErrorMeta(new HttpClientError('connect ECONNREFUSED 1.2.3.4:443', 'ECONNREFUSED'))).toEqual({ error_code: 'ECONNREFUSED' });
  });

  it('should keep the message of a blocked internal destination, naming the host and the setting allowing it', () => {
    const message = 'CSV feed: the destination 10.0.0.1 is an internal network address. To allow it, add it to outbound_requests:allow_list (OUTBOUND_REQUESTS__ALLOW_LIST).';
    expect(buildIngestionErrorMeta(new HttpClientError(message, INTERNAL_DESTINATION_ERROR_CODE)))
      .toEqual({ error_code: INTERNAL_DESTINATION_ERROR_CODE, error: message });
  });

  it('should keep the message of any other error', () => {
    expect(buildIngestionErrorMeta(new Error('Invalid JSON feed configuration'))).toEqual({ error: 'Invalid JSON feed configuration' });
  });
});
