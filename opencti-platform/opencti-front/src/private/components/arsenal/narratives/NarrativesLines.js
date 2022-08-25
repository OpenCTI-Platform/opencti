import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import {
  compose,
  pipe,
  map,
  propOr,
  pathOr,
  sortBy,
  toLower,
  prop,
  filter,
  join,
  assoc,
} from 'ramda';
import { graphql, createPaginationContainer } from 'react-relay';
import withStyles from '@mui/styles/withStyles';
import List from '@mui/material/List';
import { NarrativeLine, NarrativeLineDummy } from './NarrativeLine';
import inject18n from '../../../../components/i18n';

const styles = () => ({
  root: {
    margin: 0,
  },
});

class NarrativesLinesComponent extends Component {
  render() {
    const { data, keyword, classes } = this.props;
    const sortByNameCaseInsensitive = sortBy(compose(toLower, prop('name')));
    const filterSubnarrative = (n) => n.isSubNarrative === false;
    const filterByKeyword = (n) => keyword === ''
      || n.name.toLowerCase().indexOf(keyword.toLowerCase()) !== -1
      || n.description.toLowerCase().indexOf(keyword.toLowerCase()) !== -1
      || propOr('', 'subnarratives_text', n)
        .toLowerCase()
        .indexOf(keyword.toLowerCase()) !== -1;
    const narratives = pipe(
      pathOr([], ['narratives', 'edges']),
      map((n) => n.node),
      map((n) => assoc(
        'subnarratives_text',
        pipe(
          map((o) => `${o.node.name} ${o.node.description}`),
          join(' | '),
        )(pathOr([], ['subNarratives', 'edges'], n)),
        n,
      )),
      filter(filterSubnarrative),
      filter(filterByKeyword),
      sortByNameCaseInsensitive,
    )(data);
    return (
      <List
        component="nav"
        aria-labelledby="nested-list-subheader"
        className={classes.root}
      >
        {data
          ? map((narrative) => {
            const subNarratives = pipe(
              pathOr([], ['subNarratives', 'edges']),
              map((n) => n.node),
              filter(filterByKeyword),
              sortByNameCaseInsensitive,
            )(narrative);
            return (
                <NarrativeLine
                  key={narrative.id}
                  node={narrative}
                  subNarratives={subNarratives}
                />
            );
          }, narratives)
          : Array.from(Array(20), (e, i) => <NarrativeLineDummy key={i} />)}
      </List>
    );
  }
}

NarrativesLinesComponent.propTypes = {
  classes: PropTypes.object,
  keyword: PropTypes.string,
  data: PropTypes.object,
};

export const narrativesLinesQuery = graphql`
  query NarrativesLinesPaginationQuery($count: Int!, $cursor: ID) {
    ...NarrativesLines_data @arguments(count: $count, cursor: $cursor)
  }
`;

const NarrativesLinesFragment = createPaginationContainer(
  NarrativesLinesComponent,
  {
    data: graphql`
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
    `,
  },
  {
    direction: 'forward',
    getConnectionFromProps(props) {
      return props.data && props.data.narratives;
    },
    getFragmentVariables(prevVars, totalCount) {
      return {
        ...prevVars,
        count: totalCount,
      };
    },
    getVariables(props, { count, cursor }) {
      return {
        count,
        cursor,
      };
    },
    query: narrativesLinesQuery,
  },
);

export default compose(inject18n, withStyles(styles))(NarrativesLinesFragment);
