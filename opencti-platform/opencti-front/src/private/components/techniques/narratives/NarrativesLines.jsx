import React from 'react';
import { graphql, useFragment } from 'react-relay';
import List from '@mui/material/List';
import makeStyles from '@mui/styles/makeStyles';
import { NarrativeLine, NarrativeLineDummy } from './NarrativeLine';

const useStyles = makeStyles(() => ({
  root: {
    margin: 0,
  },
}));

export const narrativesLinesQuery = graphql`
  query NarrativesLinesPaginationQuery($count: Int!, $cursor: ID) {
    ...NarrativesLines_data @arguments(count: $count, cursor: $cursor)
  }
`;

const narrativeFragment = graphql`
  fragment NarrativesLines_data on Query
  @argumentDefinitions(
    count: { type: "Int", defaultValue: 25 }
    cursor: { type: "ID" }
  ) {
    narratives(first: $count, after: $cursor)
    @connection(key: "Pagination_narratives") {
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

export const NarrativesLines = ({ data, keyword }) => {
  const narrativeData = useFragment(narrativeFragment, data);
  const classes = useStyles();
  const filterSubnarrative = (n) => n.isSubNarrative === false;
  const filterByKeyword = (n) => keyword === ''
      || n.name.toLowerCase().indexOf(keyword.toLowerCase()) !== -1
      || (n.description ?? '').toLowerCase().indexOf(keyword.toLowerCase())
        !== -1
      || (n.subnarratives_text ?? '')
        .toLowerCase()
        .indexOf(keyword.toLowerCase()) !== -1;
  const narratives = (narrativeData?.narratives?.edges ?? [])
    .map((n) => n.node)
    .map((n) => ({
      ...n,
      subnarratives_text: (n.subNarratives?.edges ?? [])
        .map((o) => `${o.node.name} ${o.node.description}`)
        .join('|'),
    }))
    .filter(filterSubnarrative)
    .filter(filterByKeyword)
    .sort((a, b) => a.name.localeCompare(b.name));
  return (
    <List
      component="nav"
      aria-labelledby="nested-list-subheader"
      className={classes.root}
    >
      {narrativeData
        ? narratives.map((narrative) => {
          const subNarratives = (narrative.subNarratives?.edges ?? [])
            .map((n) => n.node)
            .filter(filterByKeyword)
            .sort((a, b) => a.name.localeCompare(b.name));
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

export default NarrativesLines;
