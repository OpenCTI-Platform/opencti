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
  filter,
  join,
  assoc,
} from 'ramda';
import { graphql, createPaginationContainer } from 'react-relay';
import withStyles from '@mui/styles/withStyles';
import List from '@mui/material/List';
import { AttackPatternLine, AttackPatternLineDummy } from './AttackPatternLine';
import inject18n from '../../../../components/i18n';

const styles = () => ({
  root: {
    margin: 0,
  },
});

class AttackPatternsLinesComponent extends Component {
  render() {
    const { data, keyword, classes } = this.props;
    const sortByXMitreIdCaseInsensitive = sortBy(
      compose(toLower, propOr('', 'x_mitre_id')),
    );
    const filterSubattackPattern = (n) => n.isSubAttackPattern === false;
    const filterByKeyword = (n) => keyword === ''
      || n.name.toLowerCase().indexOf(keyword.toLowerCase()) !== -1
      || n.description.toLowerCase().indexOf(keyword.toLowerCase()) !== -1
      || propOr('', 'x_mitre_id', n)
        .toLowerCase()
        .indexOf(keyword.toLowerCase()) !== -1
      || propOr('', 'subattackPatterns_text', n)
        .toLowerCase()
        .indexOf(keyword.toLowerCase()) !== -1;
    const attackPatterns = pipe(
      pathOr([], ['attackPatterns', 'edges']),
      map((n) => n.node),
      map((n) => assoc(
        'subattackPatterns_text',
        pipe(
          map(
            (o) => `${o.node.x_mitre_id} ${o.node.name} ${o.node.description}`,
          ),
          join(' | '),
        )(pathOr([], ['subAttackPatterns', 'edges'], n)),
        n,
      )),
      filter(filterSubattackPattern),
      filter(filterByKeyword),
      sortByXMitreIdCaseInsensitive,
    )(data);
    return (
      <List
        component="nav"
        aria-labelledby="nested-list-subheader"
        className={classes.root}
      >
        {data
          ? map((attackPattern) => {
            const subAttackPatterns = pipe(
              pathOr([], ['subAttackPatterns', 'edges']),
              map((n) => n.node),
              filter(filterByKeyword),
              sortByXMitreIdCaseInsensitive,
            )(attackPattern);
            return (
                <AttackPatternLine
                  key={attackPattern.id}
                  node={attackPattern}
                  subAttackPatterns={subAttackPatterns}
                />
            );
          }, attackPatterns)
          : Array.from(Array(20), (e, i) => <AttackPatternLineDummy key={i} />)}
      </List>
    );
  }
}

AttackPatternsLinesComponent.propTypes = {
  classes: PropTypes.object,
  keyword: PropTypes.string,
  data: PropTypes.object,
};

export const attackPatternsLinesQuery = graphql`
  query AttackPatternsLinesPaginationQuery(
    $orderBy: AttackPatternsOrdering
    $orderMode: OrderingMode
    $count: Int!
    $cursor: ID
  ) {
    ...AttackPatternsLines_data
      @arguments(
        orderBy: $orderBy
        orderMode: $orderMode
        count: $count
        cursor: $cursor
      )
  }
`;

const AttackPatternsLinesFragment = createPaginationContainer(
  AttackPatternsLinesComponent,
  {
    data: graphql`
      fragment AttackPatternsLines_data on Query
      @argumentDefinitions(
        orderBy: { type: "AttackPatternsOrdering", defaultValue: x_mitre_id }
        orderMode: { type: "OrderingMode", defaultValue: asc }
        count: { type: "Int", defaultValue: 25 }
        cursor: { type: "ID" }
      ) {
        attackPatterns(
          orderBy: $orderBy
          orderMode: $orderMode
          first: $count
          after: $cursor
        ) @connection(key: "Pagination_attackPatterns") {
          edges {
            node {
              id
              name
              description
              isSubAttackPattern
              x_mitre_id
              subAttackPatterns {
                edges {
                  node {
                    id
                    name
                    description
                    x_mitre_id
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
      return props.data && props.data.attackPatterns;
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
    query: attackPatternsLinesQuery,
  },
);

export default compose(
  inject18n,
  withStyles(styles),
)(AttackPatternsLinesFragment);
