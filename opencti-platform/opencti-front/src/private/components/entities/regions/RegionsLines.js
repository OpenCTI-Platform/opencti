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
  flatten,
  uniqBy,
} from 'ramda';
import { graphql, createRefetchContainer } from 'react-relay';
import withStyles from '@mui/styles/withStyles';
import List from '@mui/material/List';
import { RegionLine, RegionLineDummy } from './RegionLine';
import inject18n from '../../../../components/i18n';
import Security, { KNOWLEDGE_KNUPDATE } from '../../../../utils/Security';
import RegionOrCountryCreation from '../common/RegionOrCountryCreation';

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
      || propOr('', 'subregions_text', n)
        .toLowerCase()
        .indexOf(keyword.toLowerCase()) !== -1
      || propOr('', 'countries_text', n)
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
      map((n) => assoc(
        'countries_text',
        pipe(
          map((o) => o.node.countries.edges),
          flatten,
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
      <div>
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
                map((n) => assoc(
                  'countries_text',
                  pipe(
                    map((o) => `${o.node.name} ${o.node.description}`),
                    join(' | '),
                  )(pathOr([], ['countries', 'edges'], n)),
                  n,
                )),
                filter(filterByKeyword),
                sortByNameCaseInsensitive,
              )(region);
              const countries = pipe(
                pathOr([], ['countries', 'edges']),
                map((n) => n.node),
                filter(filterByKeyword),
                sortByNameCaseInsensitive,
                uniqBy(prop('id')),
              )(region);
              return (
                  <RegionLine
                    key={region.id}
                    node={region}
                    countries={countries}
                    subRegions={subRegions}
                    keyword={keyword}
                  />
              );
            }, regions)
            : Array.from(Array(20), (e, i) => <RegionLineDummy key={i} />)}
        </List>
        <Security needs={[KNOWLEDGE_KNUPDATE]}>
          <RegionOrCountryCreation onCreate={this.props.relay.refetch} />
        </Security>
      </div>
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
    ...RegionsLines_data
  }
`;

const RegionsLinesFragment = createRefetchContainer(
  RegionsLinesComponent,
  {
    data: graphql`
      fragment RegionsLines_data on Query {
        regions(first: $count, after: $cursor) {
          edges {
            node {
              id
              name
              isSubRegion
              subRegions {
                edges {
                  node {
                    id
                    name
                    countries {
                      edges {
                        node {
                          id
                          name
                        }
                      }
                    }
                  }
                }
              }
              countries {
                edges {
                  node {
                    id
                    name
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
  regionsLinesQuery,
);

export default compose(inject18n, withStyles(styles))(RegionsLinesFragment);
