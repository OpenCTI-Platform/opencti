import { graphql } from 'react-relay';
import { fetchQuery } from '../../../../relay/environment';
import type { countryNamesQuery } from './__generated__/countryNamesQuery.graphql';

const countryNamesQuery = graphql`
  query countryNamesQuery {
    countries(first: 500) {
      edges {
        node {
          name
          x_opencti_aliases
        }
      }
    }
  }
`;

let pending: Promise<Map<string, string> | null> | null = null;

export const loadCountryNames = () => {
  pending ??= fetchQuery<countryNamesQuery>(countryNamesQuery)
    .toPromise()
    .then((data) => {
      const names = new Map<string, string>();
      for (const { node } of data?.countries?.edges ?? []) {
        for (const alias of node.x_opencti_aliases ?? []) {
          if (alias) names.set(alias, node.name);
        }
      }
      return names;
    })
    .catch(() => null);
  return pending;
};
