import React from 'react';
import { graphql, usePaginationFragment } from 'react-relay';
import { Link } from 'react-router';
import { useTheme } from '@mui/styles';
import { Text } from '@filigran/design-system';
import Button from '@common/button/Button';
import Label from '../../../../components/common/label/Label';
import ItemIcon from '../../../../components/ItemIcon';
import { useFormatter } from '../../../../components/i18n';
import type { Theme } from '../../../../components/Theme';
import { resolveLink } from '../../../../utils/Entity';
import { HuntRunResultsPaginationQuery } from './__generated__/HuntRunResultsPaginationQuery.graphql';
import { HuntRunResults_data$key } from './__generated__/HuntRunResults_data.graphql';

export const HUNT_RUN_RESULTS_PAGE_SIZE = 25;

export const huntRunResultsFragment = graphql`
  fragment HuntRunResults_data on Query
  @refetchable(queryName: "HuntRunResultsPaginationQuery")
  @argumentDefinitions(
    id: { type: "String!" }
    count: { type: "Int", defaultValue: 25 }
    cursor: { type: "ID" }
  ) {
    huntRun(id: $id) {
      results(first: $count, after: $cursor) @connection(key: "HuntRunResults_results") {
        pageInfo {
          globalCount
          hasNextPage
          endCursor
        }
        edges {
          node {
            ... on BasicObject {
              id
              entity_type
            }
            ... on StixObject {
              representative {
                main
              }
            }
            ... on StixRelationship {
              representative {
                main
              }
            }
            ... on StixCoreRelationship {
              from {
                ... on BasicObject {
                  id
                  entity_type
                }
              }
            }
          }
        }
      }
    }
  }
`;

interface ResultNode {
  readonly id?: string;
  readonly entity_type?: string;
  readonly from?: { readonly id?: string; readonly entity_type?: string } | null;
}

/**
 * The page of a result: its own route, or for a relationship without one, the relationship page under its source
 * entity. Null when neither exists, the result is then shown without a link.
 */
export const huntRunResultLink = (result: ResultNode): string | null => {
  if (!result.id) {
    return null;
  }
  const route = resolveLink(result.entity_type);
  if (route) {
    return `${route}/${result.id}`;
  }
  const fromRoute = result.from?.id && result.from.entity_type ? resolveLink(result.from.entity_type) : null;
  return fromRoute ? `${fromRoute}/${result.from?.id}/knowledge/relations/${result.id}` : null;
};

/** The objects a run created that the user can read, a page at a time, with their total. */
const HuntRunResults = ({ data }: { data: HuntRunResults_data$key }) => {
  const theme = useTheme<Theme>();
  const { t_i18n, n } = useFormatter();
  const { data: { huntRun }, hasNext, loadNext, isLoadingNext } = usePaginationFragment<HuntRunResultsPaginationQuery, HuntRunResults_data$key>(
    huntRunResultsFragment,
    data,
  );
  const results = (huntRun?.results?.edges ?? []).map((edge) => edge?.node).filter((node) => !!node?.id);
  if (results.length === 0) {
    return null;
  }
  const total = huntRun?.results?.pageInfo.globalCount ?? results.length;
  return (
    <>
      <Label sx={{ marginTop: 2 }}>{t_i18n('Results')}</Label>
      <ul style={{ listStyle: 'none', margin: 0, padding: 0 }} data-testid="hunt-run-results">
        {results.map((result) => {
          if (!result) return null;
          const link = huntRunResultLink(result);
          const name = result.representative?.main ?? result.id;
          return (
            <li key={result.id} style={{ display: 'flex', alignItems: 'center', gap: theme.spacing(1), padding: theme.spacing(0.5, 0) }}>
              <ItemIcon type={result.entity_type} />
              {link ? <Link to={link}>{name}</Link> : <Text variant="content-compact" as="span">{name}</Text>}
            </li>
          );
        })}
      </ul>
      <div style={{ display: 'flex', alignItems: 'center', gap: theme.spacing(1.5), marginTop: theme.spacing(1) }}>
        <Text variant="content-caption" as="span">
          {t_i18n('{shown} of {total} results', { values: { shown: n(results.length), total: n(total) } })}
        </Text>
        {hasNext && (
          <Button
            variant="secondary"
            size="small"
            disabled={isLoadingNext}
            onClick={() => loadNext(HUNT_RUN_RESULTS_PAGE_SIZE)}
            data-testid="hunt-run-results-more"
          >
            {t_i18n('Show more')}
          </Button>
        )}
      </div>
    </>
  );
};

export default HuntRunResults;
