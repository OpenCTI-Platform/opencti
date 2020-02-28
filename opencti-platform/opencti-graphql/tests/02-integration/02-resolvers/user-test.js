import gql from 'graphql-tag';
import uuid from 'uuid/v4';
import { authentication } from '../../../src/domain/user';
import { queryAsAdmin } from '../../utils/testQuery';

// region queries
const USER_EMAIL = `${uuid()}@opencti.io`;
const CREATE_QUERY = gql`
  mutation UserAdd($input: UserAddInput) {
    userAdd(input: $input) {
      name
      user_email
      firstname
      lastname
    }
  }
`;
const LOGIN_QUERY = gql`
  mutation Token($input: UserLoginInput) {
    token(input: $input)
  }
`;
// endregion

describe('User resolver standard behavior', () => {
  it('should user created', async () => {
    const USER_TO_CREATE = {
      input: {
        name: 'user',
        password: 'user',
        user_email: USER_EMAIL,
        firstname: 'User',
        lastname: 'OpenCTI'
      }
    };
    const res = await queryAsAdmin({ query: CREATE_QUERY, variables: USER_TO_CREATE });
    expect(res).not.toBeNull();
    expect(res.data).not.toBeNull();
    expect(res.data.userAdd).not.toBeNull();
    expect(res.data.userAdd.user_email).toBe(USER_EMAIL);
    expect(res.data.userAdd.lastname).toBe('OpenCTI');
  });

  it('should user login', async () => {
    const LOGIN_INFO = {
      input: {
        email: USER_EMAIL,
        password: 'user'
      }
    };
    const res = await queryAsAdmin({ query: LOGIN_QUERY, variables: LOGIN_INFO });
    expect(res).not.toBeNull();
    expect(res.data).not.toBeNull();
    expect(res.data.token).toBeDefined();
    const user = await authentication(res.data.token);
    expect(user.user_email).toBe(USER_EMAIL);
  });
});
