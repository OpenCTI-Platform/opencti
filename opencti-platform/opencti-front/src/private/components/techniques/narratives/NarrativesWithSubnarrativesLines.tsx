import React, { FunctionComponent } from 'react';
import { graphql, PreloadedQuery } from 'react-relay';
import { NarrativesLinesPaginationQuery, NarrativesLinesPaginationQuery$variables } from '@components/techniques/narratives/__generated__/NarrativesLinesPaginationQuery.graphql';
import { NarrativeLine_node$data } from '@components/techniques/narratives/__generated__/NarrativeLine_node.graphql';
import { narrativesLinesQuery } from '@components/techniques/narratives/NarrativesLines';
import { NarrativesWithSubnarrativesLines_data$key } from '@components/techniques/narratives/__generated__/NarrativesWithSubnarrativesLines_data.graphql';
import makeStyles from '@mui/styles/makeStyles';
import List from '@mui/material/List';
import { NarrativeLine, NarrativeLineDummy } from './NarrativeLine';
import { DataColumns } from '../../../../components/list_lines';
import usePreloadedPaginationFragment from '../../../../utils/hooks/usePreloadedPaginationFragment';

const useStyles = makeStyles(() => ({
  root: {
    margin: 0,
  },
}));

interface NarrativesWithSubnarrativesLinesProps {
  queryRef: PreloadedQuery<NarrativesLinesPaginationQuery>;
  paginationOptions: NarrativesLinesPaginationQuery$variables;
  onToggleEntity: (
    entity: NarrativeLine_node$data,
    event: React.SyntheticEvent
  ) => void;
  redirectionMode?: string;
  keyword: string,
}

const narrativesWithSubnarrativesLinesFragment = graphql`
    fragment NarrativesWithSubnarrativesLines_data on Query
    @argumentDefinitions(
        search: { type: "String" }
        count: { type: "Int", defaultValue: 25 }
        cursor: { type: "ID" }
        orderBy: { type: "NarrativesOrdering", defaultValue: name }
        orderMode: { type: "OrderingMode", defaultValue: asc }
        filters: { type: "FilterGroup" }
    )
    @refetchable(queryName: "NarrativesWithSubnarrativesLinesRefetchQuery") {
        narratives(
            search: $search
            first: $count
            after: $cursor
            orderBy: $orderBy
            orderMode: $orderMode
            filters: $filters
        ) @connection(key: "Pagination_narratives") {
            edges {
                node {
                    id
                    name
                    description
                    isSubNarrative
                    subNarratives {
                        edges {
                            node {
                                id
                                name
                                description
                            }
                        }
                    }
                    ...NarrativeWithSubnarrativeLine_node
                }
            }
            pageInfo {
                endCursor
                hasNextPage
                globalCount
            }
        }
    }
`;

const NarrativesWithSubnarrativesLines: FunctionComponent<NarrativesWithSubnarrativesLinesProps> = ({
  queryRef,
  keyword,
}) => {
  const classes = useStyles();
  const { data } = usePreloadedPaginationFragment<
  NarrativesLinesPaginationQuery,
  NarrativesWithSubnarrativesLines_data$key
  >({
    linesQuery: narrativesLinesQuery,
    linesFragment: narrativesWithSubnarrativesLinesFragment,
    queryRef,
    nodePath: ['narratives', 'pageInfo', 'globalCount'],
  });
  const filterByKeyword = (n) => keyword === ''
      || n.name.toLowerCase().indexOf(keyword.toLowerCase()) !== -1
      || (n.description ?? '').toLowerCase().indexOf(keyword.toLowerCase())
      !== -1
      || (n.subnarratives_text ?? '')
        .toLowerCase()
        .indexOf(keyword.toLowerCase()) !== -1;

  const narratives = (data?.narratives?.edges ?? []).map((n) => n?.node)
    .map((n) => ({
      ...n,
      isSubNarrative: n?.isSubNarrative ?? false,
      subNarratives: n?.subNarratives ?? { edges: [] },
      subnarratives_text: ((n?.subNarratives ?? {}).edges ?? []).map((o) => `${o?.node.name} ${o?.node.description}`).join(' | '),
    }))
    .filter((n) => n.isSubNarrative === false)
    .filter(filterByKeyword)
    .sort((a, b) => (a?.name ?? '').localeCompare(b?.name ?? ''));

  return (
    <List
      component="nav"
      aria-labelledby="nested-list-subheader"
      className={classes.root}
    >
      {data
        ? narratives.map((narrative) => {
          const subNarratives = (narrative.subNarratives.edges ?? [])
            .map((n) => n?.node)
            .filter(filterByKeyword)
            .sort((a, b) => (a?.name ?? '').localeCompare(b?.name ?? ''));
          return (
            <NarrativeLine
              key={narrative.id}
              node={narrative}
              subNarratives={subNarratives}
            />
          );
        })
        : Array.from(Array(20), (e, i) => <NarrativeLineDummy key={i} />)}
    </List>
  );
};

export default NarrativesWithSubnarrativesLines;
