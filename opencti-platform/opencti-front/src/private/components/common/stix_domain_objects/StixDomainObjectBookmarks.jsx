import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import * as R from 'ramda';
import { graphql, createPaginationContainer } from 'react-relay';
import withStyles from '@mui/styles/withStyles';
import { InformationOutline } from 'mdi-material-ui';
import { Tooltip, Typography } from '@components';
import { StixDomainObjectBookmark, StixDomainObjectBookmarkDummy } from './StixDomainObjectBookmark';
import inject18n from '../../../../components/i18n';
import ListCardsContent from '../../../../components/list_cards/ListCardsContent';

const styles = () => ({
  container: {
    margin: '0 0 10px 0',
  },
});

class StixDomainObjectBookmarksComponent extends Component {
  componentDidUpdate(prevProps) {
    const prevBookmarks = R.pathOr([], ['bookmarks', 'edges'], prevProps.data);
    const bookmarks = R.pathOr([], ['bookmarks', 'edges'], this.props.data);
    const diff = R.symmetricDifferenceWith(
      (x, y) => x.node.id === y.node.id,
      prevBookmarks,
      bookmarks,
    );
    if (diff.length > 0) {
      this.props.setBookmarkList(bookmarks);
    }
  }

  render() {
    const { classes, data, t, relay } = this.props;
    const bookmarks = R.pathOr([], ['bookmarks', 'edges'], data);
    if (bookmarks.length > 0) {
      return (
        <div className={classes.container}>
          <Typography
            variant="h4"
            gutterBottom={true}
            style={{ padding: '0 0 5px 18px', float: 'left' }}
          >
            {t('Favorite entities')}
          </Typography>
          <Tooltip
            title={t('Only the first 8 favorite entities are displayed here. You can use custom dashboard favorite widget to have them all in your dashboard(s)')}
          >
            <InformationOutline
              fontSize="small"
              color="primary"
              style={{ cursor: 'default', float: 'left', margin: '-3px 0 0 10px' }}
            />
          </Tooltip>
          <div className="clearfix" />
          <ListCardsContent
            loadMore={relay.loadMore.bind(this)}
            hasMore={relay.hasMore.bind(this)}
            isLoading={relay.isLoading.bind(this)}
            dataList={R.take(8, bookmarks)}
            CardComponent={<StixDomainObjectBookmark />}
            DummyCardComponent={<StixDomainObjectBookmarkDummy />}
            rowHeight={90}
          />
        </div>
      );
    }
    return <span />;
  }
}

StixDomainObjectBookmarksComponent.propTypes = {
  relay: PropTypes.object,
  data: PropTypes.object,
  setBookmarkList: PropTypes.func,
};

export const stixDomainObjectBookmarksQuery = graphql`
  query StixDomainObjectBookmarksQuery($types: [String]) {
    ...StixDomainObjectBookmarks_bookmarks @arguments(types: $types)
  }
`;

export const stixDomainobjectBookmarksFragment = graphql`
  fragment StixDomainObjectBookmarks_bookmarks on Query
  @argumentDefinitions(types: { type: "[String]" }) {
    bookmarks(types: $types, first: 200)
      @connection(key: "Pagination_bookmarks") {
      edges {
        node {
          id
          ...StixDomainObjectBookmark_node
        }
      }
    }
  }
`;

const StixDomainObjectBookmarksFragment = createPaginationContainer(
  StixDomainObjectBookmarksComponent,
  {
    data: stixDomainobjectBookmarksFragment,
  },
  {
    direction: 'forward',
    getConnectionFromProps(props) {
      return props.data && props.data.bookmarks;
    },
    getFragmentVariables(prevVars, totalCount) {
      return {
        ...prevVars,
        count: totalCount,
      };
    },
    getVariables(props, { count }, fragmentVariables) {
      return {
        types: fragmentVariables.types,
        count,
      };
    },
    query: stixDomainObjectBookmarksQuery,
  },
);

export default R.compose(
  inject18n,
  withStyles(styles),
)(StixDomainObjectBookmarksFragment);
