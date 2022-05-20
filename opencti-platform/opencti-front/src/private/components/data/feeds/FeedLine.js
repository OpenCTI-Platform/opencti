import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import { graphql, createFragmentContainer } from 'react-relay';
import withStyles from '@mui/styles/withStyles';
import ListItem from '@mui/material/ListItem';
import ListItemIcon from '@mui/material/ListItemIcon';
import ListItemText from '@mui/material/ListItemText';
import ListItemSecondaryAction from '@mui/material/ListItemSecondaryAction';
import { MoreVert } from '@mui/icons-material';
import { FileDelimitedOutline } from 'mdi-material-ui';
import { compose, last, map, toPairs } from 'ramda';
import Chip from '@mui/material/Chip';
import Slide from '@mui/material/Slide';
import Skeleton from '@mui/material/Skeleton';
import { truncate } from '../../../../utils/String';
import FeedPopover from './FeedPopover';
import inject18n from '../../../../components/i18n';

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
    height: 20,
    fontSize: 13,
    float: 'left',
    whiteSpace: 'nowrap',
    overflow: 'hidden',
    textOverflow: 'ellipsis',
    paddingRight: 5,
  },
  goIcon: {
    position: 'absolute',
    right: -10,
  },
  itemIconDisabled: {
    color: theme.palette.grey[700],
  },
  placeholder: {
    display: 'inline-block',
    height: '1em',
    backgroundColor: theme.palette.grey[700],
  },
  filter: {
    fontSize: 12,
    lineHeight: '12px',
    height: 20,
    marginRight: 7,
    borderRadius: 10,
  },
  operator: {
    fontFamily: 'Consolas, monaco, monospace',
    backgroundColor: theme.palette.background.accent,
    height: 20,
    marginRight: 10,
  },
});

class FeedLineLineComponent extends Component {
  render() {
    const { t, classes, node, dataColumns, paginationOptions } = this.props;
    const filters = JSON.parse(node.filters || '{}');
    return (
      <ListItem
        classes={{ root: classes.item }}
        divider={true}
        button={true}
        component="a"
        href={`/feeds/${node.id}`}
      >
        <ListItemIcon classes={{ root: classes.itemIcon }}>
          <FileDelimitedOutline />
        </ListItemIcon>
        <ListItemText
          primary={
            <div>
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
                {node.feed_attributes.map((n) => n.attribute).join(', ')}
              </div>
              <div
                className={classes.bodyItem}
                style={{ width: dataColumns.filters.width }}
              >
                {map((currentFilter) => {
                  const label = `${truncate(
                    t(`filter_${currentFilter[0]}`),
                    20,
                  )}`;
                  const values = (
                    <span>
                      {map(
                        (n) => (
                          <span key={n.value}>
                            {n.value && n.value.length > 0
                              ? truncate(n.value, 15)
                              : t('No label')}{' '}
                            {last(currentFilter[1]).value !== n.value && (
                              <code>OR</code>
                            )}{' '}
                          </span>
                        ),
                        currentFilter[1],
                      )}
                    </span>
                  );
                  return (
                    <span>
                      <Chip
                        key={currentFilter[0]}
                        classes={{ root: classes.filter }}
                        label={
                          <div>
                            <strong>{label}</strong>: {values}
                          </div>
                        }
                      />
                      {last(toPairs(filters))[0] !== currentFilter[0] && (
                        <Chip
                          classes={{ root: classes.operator }}
                          label={t('AND')}
                        />
                      )}
                    </span>
                  );
                }, toPairs(filters))}
              </div>
            </div>
          }
        />
        <ListItemSecondaryAction>
          <FeedPopover feedId={node.id} paginationOptions={paginationOptions} />
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
            <div>
              <div
                className={classes.bodyItem}
                style={{ width: dataColumns.name.width }}
              >
                <Skeleton
                  animation="wave"
                  variant="rectangular"
                  width="90%"
                  height="100%"
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
                  height="100%"
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
                  height="100%"
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
                  height="100%"
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
                  height="100%"
                />
              </div>
            </div>
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
