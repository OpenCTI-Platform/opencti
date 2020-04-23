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
import { createPaginationContainer } from 'react-relay';
import graphql from 'babel-plugin-relay/macro';
import { withStyles } from '@material-ui/core';
import List from '@material-ui/core/List';
import { RegionLine, RegionLineDummy } from './RegionLine';
import inject18n from '../../../../components/i18n';

const styles = () => ({
  root: {
    margin: 0,
  },
});

class RegionsLinesComponent extends Component {
  render() {
    const { data, keyword, classes } = this.props;
    const sortByNameCaseInsensitive = sortBy(compose(toLower, prop('name')));
    const filterSubregion = (n) => n.isSubRegion === false;
    const filterByKeyword = (n) => keyword === ''
      || n.name.toLowerCase().indexOf(keyword.toLowerCase()) !== -1
      || n.description.toLowerCase().indexOf(keyword.toLowerCase()) !== -1
      || propOr('', 'subregions_text', n)
        .toLowerCase()
        .indexOf(keyword.toLowerCase()) !== -1;
    const regions = pipe(
      pathOr([], ['regions', 'edges']),
      map((n) => n.node),
      map((n) => assoc(
        'subregions_text',
        pipe(
          map((o) => `${o.node.name} ${o.node.description}`),
          join(' | '),
        )(pathOr([], ['subRegions', 'edges'], n)),
        n,
      )),
      filter(filterSubregion),
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
          ? map((region) => {
            const subRegions = pipe(
              pathOr([], ['subRegions', 'edges']),
              map((n) => n.node),
              filter(filterByKeyword),
              sortByNameCaseInsensitive,
            )(region);
            return (
                <RegionLine
                  key={region.id}
                  node={region}
                  subRegions={subRegions}
                />
            );
          }, regions)
          : Array.from(Array(20), (e, i) => <RegionLineDummy key={i} />)}
      </List>
    );
  }
}

RegionsLinesComponent.propTypes = {
  classes: PropTypes.object,
  keyword: PropTypes.string,
  data: PropTypes.object,
};

export const regionsLinesQuery = graphql`
  query RegionsLinesPaginationQuery($count: Int!, $cursor: ID) {
    ...RegionsLines_data @arguments(count: $count, cursor: $cursor)
  }
`;

const RegionsLinesFragment = createPaginationContainer(
  RegionsLinesComponent,
  {
    data: graphql`
      fragment RegionsLines_data on Query
        @argumentDefinitions(
          count: { type: "Int", defaultValue: 25 }
          cursor: { type: "ID" }
        ) {
        regions(first: $count, after: $cursor)
          @connection(key: "Pagination_regions") {
          edges {
            node {
              id
              name
              description
              isSubRegion
              subRegions {
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
      return props.data && props.data.regions;
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
    query: regionsLinesQuery,
  },
);

export default compose(inject18n, withStyles(styles))(RegionsLinesFragment);
