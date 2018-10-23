import {
  generateOpenCTIWebToken,
  OPENCTI_ISSUER,
  OPENCTI_DEFAULT_DURATION
} from '../user';

test('Validation of roles assertion', () => {
  const webToken = generateOpenCTIWebToken('test@test.com');
  expect(webToken.id).toEqual('42132b9c-1816-5b4a-97f2-32c7529b85ee');
  expect(webToken.issuer).toEqual(OPENCTI_ISSUER);
  expect(webToken.duration).toEqual(OPENCTI_DEFAULT_DURATION);
});
