import { generateOpenCTIWebToken } from '../../../src/domain/user';
import { OPENCTI_DEFAULT_DURATION, OPENCTI_ISSUER } from '../../../src/config/conf';

test('Validation of roles assertion', () => {
  const webToken = generateOpenCTIWebToken();
  expect(webToken.issuer).toEqual(OPENCTI_ISSUER);
  expect(webToken.duration).toEqual(OPENCTI_DEFAULT_DURATION);
});
