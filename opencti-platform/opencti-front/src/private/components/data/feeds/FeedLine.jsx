import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import { createFragmentContainer, graphql } from 'react-relay';
import withStyles from '@mui/styles/withStyles';
import ListItem from '@mui/material/ListItem';
import ListItemIcon from '@mui/material/ListItemIcon';
import ListItemText from '@mui/material/ListItemText';
import ListItemSecondaryAction from '@mui/material/ListItemSecondaryAction';
import { MoreVert } from '@mui/icons-material';
import { FileDelimitedOutline } from 'mdi-material-ui';
import { compose } from 'ramda';
import Slide from '@mui/material/Slide';
import Skeleton from '@mui/material/Skeleton';
import FeedPopover from './FeedPopover';
import inject18n from '../../../../components/i18n';
import FilterIconButton from '../../../../components/FilterIconButton';
import { deserializeFilterGroupForFrontend } from '../../../../utils/filters/filtersUtils';
import { TAXIIAPI_SETCOLLECTIONS } from '../../../../utils/hooks/useGranted';
import Security from '../../../../utils/Security';

const Transition = React.forwardRef((props, ref) => (
  <Slide direction="up" ref={ref} {...props} />
));
Transition.displayName = 'TransitionSlide';

const styles = (theme) => ({
  item: {
    paddingLeft: 10,
    height: 50,
  },
  itemIcon: {
    color: theme.palette.primary.main,
  },
  bodyItem: {
    height: 40,
    display: 'flex',
    alignItems: 'center',
    fontSize: 13,
    float: 'left',
    whiteSpace: 'nowrap',
    overflow: 'hidden',
    textOverflow: 'ellipsis',
    paddingRight: 10,
  },
  filtersItem: {
    height: 40,
    display: 'flex',
    alignItems: 'center',
    float: 'left',
    paddingRight: 10,
  },
  itemIconDisabled: {
    color: theme.palette.grey[700],
  },
  placeholder: {
    display: 'inline-block',
    height: '1em',
    backgroundColor: theme.palette.grey[700],
  },
});

class FeedLineLineComponent extends Component {
  render() {
    const { classes, node, dataColumns, paginationOptions } = this.props;
    const filters = deserializeFilterGroupForFrontend(node.filters);
    return (
      <ListItem
        classes={{ root: classes.item }}
        divider={true}
        button={true}
        component="a"
        href={`/feeds/${node.id}`}
        target={'_blank'} // open in new tab
      >
        <ListItemIcon classes={{ root: classes.itemIcon }}>
          <FileDelimitedOutline />
        </ListItemIcon>
        <ListItemText
          primary={
            <>
              <div
                className={classes.bodyItem}
                style={{ width: dataColumns.name.width }}
              >
                {node.name}
              </div>
              <div
                className={classes.bodyItem}
                style={{ width: dataColumns.feed_types.width }}
              >
                {node.feed_types.join(', ')}
              </div>
              <div
                className={classes.bodyItem}
                style={{ width: dataColumns.rolling_time.width }}
              >
                <code>{node.rolling_time}</code>
              </div>
              <div
                className={classes.bodyItem}
                style={{ width: dataColumns.columns.width }}
              >
                {node.feed_attributes.map((n) => n.attribute).join(`${node.separator} `)}
              </div>
              <div
                className={classes.filtersItem}
                style={{ width: dataColumns.filters.width }}
              >
                <FilterIconButton
                  filters={filters}
                  styleNumber={3}
                  dataColumns={dataColumns}
                />
              </div>
            </>
          }
        />
        <ListItemSecondaryAction>
          <Security needs={[TAXIIAPI_SETCOLLECTIONS]}>
            <FeedPopover feedId={node.id} paginationOptions={paginationOptions} />
          </Security>
        </ListItemSecondaryAction>
      </ListItem>
    );
  }
}

FeedLineLineComponent.propTypes = {
  dataColumns: PropTypes.object,
  node: PropTypes.object,
  paginationOptions: PropTypes.object,
  me: PropTypes.object,
  classes: PropTypes.object,
  fd: PropTypes.func,
};

const FeedLineFragment = createFragmentContainer(FeedLineLineComponent, {
  node: graphql`
    fragment FeedLine_node on Feed {
      id
      name
      separator
      rolling_time
      filters
      include_header
      feed_types
      feed_attributes {
        attribute
        mappings {
          type
          attribute
        }
      }
    }
  `,
});

export const FeedLine = compose(
  inject18n,
  withStyles(styles),
)(FeedLineFragment);

class FeedDummyComponent extends Component {
  render() {
    const { classes, dataColumns } = this.props;
    return (
      <ListItem classes={{ root: classes.item }} divider={true}>
        <ListItemIcon classes={{ root: classes.itemIcon }}>
          <Skeleton
            animation="wave"
            variant="circular"
            width={30}
            height={30}
          />
        </ListItemIcon>
        <ListItemText
          primary={
            <>
              <div
                className={classes.bodyItem}
                style={{ width: dataColumns.name.width }}
              >
                <Skeleton
                  animation="wave"
                  variant="rectangular"
                  width="90%"
                  height="50%"
                />
              </div>
              <div
                className={classes.bodyItem}
                style={{ width: dataColumns.feed_types.width }}
              >
                <Skeleton
                  animation="wave"
                  variant="rectangular"
                  width="90%"
                  height="50%"
                />
              </div>
              <div
                className={classes.bodyItem}
                style={{ width: dataColumns.rolling_time.width }}
              >
                <Skeleton
                  animation="wave"
                  variant="rectangular"
                  width="90%"
                  height="50%"
                />
              </div>
              <div
                className={classes.bodyItem}
                style={{ width: dataColumns.columns.width }}
              >
                <Skeleton
                  animation="wave"
                  variant="rectangular"
                  width="90%"
                  height="50%"
                />
              </div>
              <div
                className={classes.bodyItem}
                style={{ width: dataColumns.filters.width }}
              >
                <Skeleton
                  animation="wave"
                  variant="rectangular"
                  width="90%"
                  height="50%"
                />
              </div>
            </>
          }
        />
        <ListItemSecondaryAction classes={{ root: classes.itemIconDisabled }}>
          <MoreVert />
        </ListItemSecondaryAction>
      </ListItem>
    );
  }
}

FeedDummyComponent.propTypes = {
  dataColumns: PropTypes.object,
  classes: PropTypes.object,
};

export const FeedLineDummy = compose(
  inject18n,
  withStyles(styles),
)(FeedDummyComponent);
