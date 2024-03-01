import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import { compose, pipe, map, pathOr, sortBy, toLower, prop, filter, join, assoc } from 'ramda';
import { graphql, createPaginationContainer } from 'react-relay';
import withStyles from '@mui/styles/withStyles';
import List from '@mui/material/List';
import { SectorLine, SectorLineDummy } from './SectorLine';
import inject18n from '../../../../components/i18n';

const styles = () => ({
  root: {
    margin: 0,
  },
});

class SectorsLinesComponent extends Component {
  render() {
    const { data, keyword, classes } = this.props;
    const sortByNameCaseInsensitive = sortBy(compose(toLower, prop('name')));
    const filterSubsector = (n) => n.isSubSector === false;
    const filterByKeyword = (n) => keyword === ''
      || n.name.toLowerCase().indexOf(keyword.toLowerCase()) !== -1
      || (n.description ?? '').toLowerCase().indexOf(keyword.toLowerCase())
        !== -1
      || (n.subsectors_text ?? '').toLowerCase().indexOf(keyword.toLowerCase())
        !== -1;
    const sectors = pipe(
      pathOr([], ['sectors', 'edges']),
      map((n) => n.node),
      map((n) => assoc(
        'subsectors_text',
        pipe(
          map((o) => `${o.node.name} ${o.node.description}`),
          join(' | '),
        )(pathOr([], ['subSectors', 'edges'], n)),
        n,
      )),
      filter(filterSubsector),
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
          ? map((sector) => {
            const subSectors = pipe(
              pathOr([], ['subSectors', 'edges']),
              map((n) => n.node),
              filter(filterByKeyword),
              sortByNameCaseInsensitive,
            )(sector);
            return (
              <SectorLine
                key={sector.id}
                node={sector}
                subSectors={subSectors}
              />
            );
          }, sectors)
          : Array.from(Array(20), (e, i) => <SectorLineDummy key={i} />)}
      </List>
    );
  }
}

SectorsLinesComponent.propTypes = {
  classes: PropTypes.object,
  keyword: PropTypes.string,
  data: PropTypes.object,
};

export const sectorsLinesQuery = graphql`
  query SectorsLinesPaginationQuery($count: Int, $cursor: ID) {
    ...SectorsLines_data @arguments(count: $count, cursor: $cursor)
  }
`;

const SectorsLinesFragment = createPaginationContainer(
  SectorsLinesComponent,
  {
    data: graphql`
      fragment SectorsLines_data on Query
      @argumentDefinitions(
        count: { type: "Int", defaultValue: 25 }
        cursor: { type: "ID" }
      ) {
        sectors(first: $count, after: $cursor)
          @connection(key: "Pagination_sectors") {
          edges {
            node {
              id
              name
              description
              isSubSector
              subSectors {
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
      return props.data && props.data.sectors;
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
    query: sectorsLinesQuery,
  },
);

export default compose(inject18n, withStyles(styles))(SectorsLinesFragment);
