import gql from 'graphql-tag';
import { describe, expect, it } from 'vitest';
import { adminQuery, queryAsAdmin, ADMIN_USER } from '../../utils/testQuery';

const TOKEN_ADD_MUTATION = gql`
  mutation UserTokenAdd($input: UserTokenAddInput!) {
    userTokenAdd(input: $input) {
      token_id
      plaintext_token
      masked_token
      expires_at
    }
  }
`;

const USER_QUERY = gql`
  query User($id: String!) {
    user(id: $id) {
      id
      api_tokens {
        id
        name
        masked_token
        expires_at
      }
    }
  }
`;

describe('User Token behavior', () => {
  it('should generate a new API token', async () => {
    // 1. Generate Token
    const input = {
      description: 'Integration Test Token',
      duration: 'Runs_30', // Need to check valid duration enum values. 
      // user-domain.ts used TokenDuration enum logic.
      // Schema likely has 'Days_30' etc. 
      // Let's use 'Days_30' as seen in user-domain.ts mapping.
      // Wait, user-domain.ts mapped 'Days_30' string from input?
      // Let's check TokenDuration enum in generated types if possible. 
      // Or just try 'Days_30'.
    };

    // Actually, let's use a safe value or check schema.
    // In user-domain.ts: [TokenDuration.Days_30]: 30
    // If TokenDuration is an enum in GraphQL, I should provide the string value.

    const mutationResult = await adminQuery({
      query: TOKEN_ADD_MUTATION,
      variables: {
        input: {
          description: 'Integration Test Token',
          duration: 'DAYS_30'
        }
      }
    });

    if (mutationResult.errors) {
      console.error(JSON.stringify(mutationResult.errors, null, 2));
    }
    expect(mutationResult).not.toBeNull();
    expect(mutationResult.data?.userTokenAdd).toBeDefined();

    const { token_id, plaintext_token, masked_token, expires_at } = mutationResult.data.userTokenAdd;

    expect(token_id).toBeDefined();
    expect(plaintext_token).toBeDefined();
    expect(plaintext_token).toContain('flgrn_octi_tkn_');
    expect(masked_token).toContain('****');
    expect(expires_at).not.toBeNull();

    // 2. Verify Token is present on User
    const userResult = await queryAsAdmin({
      query: USER_QUERY,
      variables: { id: ADMIN_USER.id }
    });

    if (userResult.errors) {
      console.error(JSON.stringify(userResult.errors, null, 2));
    }
    const user = userResult.data?.user;
    console.log('User result:', JSON.stringify(user, null, 2));

    expect(user).toBeDefined();
    expect(user.api_tokens).toBeDefined();

    const foundToken = user.api_tokens.find((t: any) => t.id === token_id);
    expect(foundToken).toBeDefined();
    expect(foundToken.name).toEqual('Integration Test Token');
    expect(foundToken.masked_token).toEqual(masked_token);
  });
});
