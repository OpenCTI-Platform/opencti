import { describe, expect, it } from 'vitest';
import gql from 'graphql-tag';
import { queryAsAdminWithSuccess } from '../../utils/testQueryHelper';

const ABOUT_QUERY = gql`
  query About {
    about {
      buildCommit
    }
  }
`;

describe('Settings resolver', () => {
  it('should expose a nullable short build commit', async () => {
    const { data } = await queryAsAdminWithSuccess({ query: ABOUT_QUERY });
    const buildCommit = data.about?.buildCommit;

    expect(buildCommit === null || /^[0-9a-f]{7}$/i.test(buildCommit)).toBe(true);
  });
});
