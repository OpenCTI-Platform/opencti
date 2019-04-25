import { query } from '../integration-test';
import { authentication } from '../../../src/server';
import { write } from '../../../src/database/grakn';

// region queries
const CREATE_QUERY = `
    mutation UserAdd($input: UserAddInput) {
      userAdd(input: $input) {
        name
        email
        firstname
        lastname
      }
    }`;

const LOGIN_QUERY = `
    mutation Token($input: UserLoginInput) {
      token(input: $input)
    }`;
// endregion

beforeAll(() => write('match $x isa User; $z($x, $y); delete $z,$x;'));

describe('User resolver standard behavior', () => {
  it('should user created', async () => {
    const USER_TO_CREATE = {
      input: {
        name: 'admin',
        password: 'admin',
        email: 'admin@opencti.io',
        firstname: 'Administrator',
        lastname: 'OpenCTI'
      }
    };
    const res = await query({ query: CREATE_QUERY, variables: USER_TO_CREATE });
    expect(res).toMatchSnapshot();
  });

  it('should user login', async () => {
    const LOGIN_INFO = {
      input: {
        email: 'admin@opencti.io',
        password: 'admin'
      }
    };
    const res = await query({ query: LOGIN_QUERY, variables: LOGIN_INFO });
    expect(res).not.toBeNull();
    expect(res.data).not.toBeNull();
    expect(res.data.token).toBeDefined();
    const user = await authentication(res.data.token);
    expect(user.email).toBe('admin@opencti.io');
  });
});
