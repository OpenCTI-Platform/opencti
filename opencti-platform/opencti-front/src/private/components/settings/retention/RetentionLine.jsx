import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import { createFragmentContainer, graphql } from 'react-relay';
import withStyles from '@mui/styles/withStyles';
import ListItem from '@mui/material/ListItem';
import ListItemIcon from '@mui/material/ListItemIcon';
import ListItemText from '@mui/material/ListItemText';
import ListItemSecondaryAction from '@mui/material/ListItemSecondaryAction';
import { LayersClearOutlined, MoreVert } from '@mui/icons-material';
import * as R from 'ramda';
import Slide from '@mui/material/Slide';
import Skeleton from '@mui/material/Skeleton';
import inject18n from '../../../../components/i18n';
import RetentionPopover from './RetentionPopover';
import FilterIconButton from '../../../../components/FilterIconButton';

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
    paddingRight: 10,
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
});

class RetentionLineComponent extends Component {
  render() {
    const { t, classes, node, dataColumns, paginationOptions, nsdt, n } = this.props;
    const filters = JSON.parse(node.filters);
    const filterPairs = R.toPairs(filters);
    return (
      <ListItem classes={{ root: classes.item }} divider={true}>
        <ListItemIcon classes={{ root: classes.itemIcon }}>
          <LayersClearOutlined />
        </ListItemIcon>
        <ListItemText
          primary={
            <div>
              <div className={classes.bodyItem} style={{ width: dataColumns.name.width }}>
                {node.name}
              </div>
              {filterPairs.length > 0 ? (
                <FilterIconButton
                  filters={filters}
                  dataColumns={dataColumns}
                  classNameNumber={3}
                  styleNumber={3}
                />
              ) : (
                <div className={classes.bodyItem} style={{ width: dataColumns.filters.width }}>
                  <span>{t('Everything')}</span>
                </div>
              )}
              <div
                className={classes.bodyItem}
                style={{ width: dataColumns.retention.width }}
              >
                {node.max_retention} {t('day(s)')}
              </div>
              <div
                className={classes.bodyItem}
                style={{ width: dataColumns.last_execution_date.width }}
              >
                {nsdt(node.last_execution_date)}
              </div>
              <div
                className={classes.bodyItem}
                style={{ width: dataColumns.remaining_count.width }}
              >
                {n(node.remaining_count)}
              </div>
            </div>
          }
        />
        <ListItemSecondaryAction>
          <RetentionPopover
            retentionRuleId={node.id}
            paginationOptions={paginationOptions}
          />
        </ListItemSecondaryAction>
      </ListItem>
    );
  }
}

RetentionLineComponent.propTypes = {
  dataColumns: PropTypes.object,
  node: PropTypes.object,
  paginationOptions: PropTypes.object,
  me: PropTypes.object,
  classes: PropTypes.object,
  fd: PropTypes.func,
};

const RetentionLineFragment = createFragmentContainer(RetentionLineComponent, {
  node: graphql`
    fragment RetentionLine_node on RetentionRule {
      id
      name
      max_retention
      last_execution_date
      remaining_count
      filters
    }
  `,
});

export const RetentionLine = R.compose(
  inject18n,
  withStyles(styles),
)(RetentionLineFragment);

class RetentionDummyComponent extends Component {
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
                style={{ width: dataColumns.retention.width }}
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
                  width="70%"
                  height="100%"
                />
              </div>
              <div
                className={classes.bodyItem}
                style={{ width: dataColumns.last_execution_date.width }}
              >
                <Skeleton
                  animation="wave"
                  variant="rectangular"
                  width="20%"
                  height="100%"
                />
              </div>
              <div
                className={classes.bodyItem}
                style={{ width: dataColumns.remaining_count.width }}
              >
                <Skeleton
                  animation="wave"
                  variant="rectangular"
                  width="20%"
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

RetentionDummyComponent.propTypes = {
  dataColumns: PropTypes.object,
  classes: PropTypes.object,
};

export const RetentionLineDummy = R.compose(
  inject18n,
  withStyles(styles),
)(RetentionDummyComponent);
