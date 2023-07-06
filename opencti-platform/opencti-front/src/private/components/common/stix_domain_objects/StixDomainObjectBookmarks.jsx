import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import { compose, pathOr } from 'ramda';
import { graphql, createPaginationContainer } from 'react-relay';
import withStyles from '@mui/styles/withStyles';
import Typography from '@mui/material/Typography';
import * as R from 'ramda';
import {
  StixDomainObjectBookmark,
  StixDomainObjectBookmarkDummy,
} from './StixDomainObjectBookmark';
import inject18n from '../../../../components/i18n';
import ListCardsContent from '../../../../components/list_cards/ListCardsContent';

const styles = () => ({
  container: {
    margin: '0 0 30px 0',
  },
});

class StixDomainObjectBookmarksComponent extends Component {
  componentDidUpdate(prevProps) {
    const prevBookmarks = pathOr([], ['bookmarks', 'edges'], prevProps.data);
    const bookmarks = pathOr([], ['bookmarks', 'edges'], this.props.data);
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
    const bookmarks = pathOr([], ['bookmarks', 'edges'], data);
    if (bookmarks.length > 0) {
      return (
        <div className={classes.container}>
          <Typography
            variant="h4"
            gutterBottom={true}
            style={{ padding: '0 0 5px 18px' }}
          >
            {t('Favorite entities')}
          </Typography>
          <ListCardsContent
            loadMore={relay.loadMore.bind(this)}
            hasMore={relay.hasMore.bind(this)}
            isLoading={relay.isLoading.bind(this)}
            dataList={bookmarks}
            CardComponent={<StixDomainObjectBookmark />}
            DummyCardComponent={<StixDomainObjectBookmarkDummy />}
            rowHeight={90}
          />
        </div>
      );
    }
    return <div />;
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

export default compose(
  inject18n,
  withStyles(styles),
)(StixDomainObjectBookmarksFragment);
