import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import * as R from 'ramda';
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
    const sortByNameCaseInsensitive = R.sortBy(
      R.compose(R.toLower, R.prop('name')),
    );
    const filterSubnarrative = (n) => n.isSubNarrative === false;
    const filterByKeyword = (n) => keyword === ''
      || n.name.toLowerCase().indexOf(keyword.toLowerCase()) !== -1
      || (n.description ?? '').toLowerCase().indexOf(keyword.toLowerCase())
        !== -1
      || (n.subnarratives_text ?? '')
        .toLowerCase()
        .indexOf(keyword.toLowerCase()) !== -1;
    const narratives = R.pipe(
      R.pathOr([], ['narratives', 'edges']),
      R.map((n) => n.node),
      R.map((n) => R.assoc(
        'subnarratives_text',
        R.pipe(
          R.map((o) => `${o.node.name} ${o.node.description}`),
          R.join(' | '),
        )(R.pathOr([], ['subNarratives', 'edges'], n)),
        n,
      )),
      R.filter(filterSubnarrative),
      R.filter(filterByKeyword),
      sortByNameCaseInsensitive,
    )(data);
    return (
      <List
        component="nav"
        aria-labelledby="nested-list-subheader"
        className={classes.root}
      >
        {data
          ? R.map((narrative) => {
            const subNarratives = R.pipe(
              R.pathOr([], ['subNarratives', 'edges']),
              R.map((n) => n.node),
              R.filter(filterByKeyword),
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
  query NarrativesLinesPaginationQuery($count: Int, $cursor: ID) {
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

export default R.compose(
  inject18n,
  withStyles(styles),
)(NarrativesLinesFragment);
