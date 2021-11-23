import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import { createFragmentContainer } from 'react-relay';
import graphql from 'babel-plugin-relay/macro';
import { withStyles } from '@material-ui/core/styles';
import ListItem from '@material-ui/core/ListItem';
import ListItemIcon from '@material-ui/core/ListItemIcon';
import ListItemText from '@material-ui/core/ListItemText';
import ListItemSecondaryAction from '@material-ui/core/ListItemSecondaryAction';
import { MoreVert, LayersClearOutlined } from '@material-ui/icons';
import {
  compose, last, map, toPairs,
} from 'ramda';
import Chip from '@material-ui/core/Chip';
import Slide from '@material-ui/core/Slide';
import Skeleton from '@material-ui/lab/Skeleton';
import { truncate } from '../../../../utils/String';
import inject18n from '../../../../components/i18n';
import RetentionPopover from './RetentionPopover';

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
    backgroundColor: theme.palette.background.chip,
    height: 20,
    marginRight: 10,
  },
});

class RetentionLineComponent extends Component {
  render() {
    const {
      t, classes, node, dataColumns, paginationOptions, nsdt,
    } = this.props;
    const filters = JSON.parse(node.filters);
    const filterPairs = toPairs(filters);
    return (
      <ListItem classes={{ root: classes.item }} divider={true}>
        <ListItemIcon classes={{ root: classes.itemIcon }}>
          <LayersClearOutlined />
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
                style={{ width: dataColumns.filters.width }}
              >
                {filterPairs.length > 0 ? map((currentFilter) => {
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
                }, filterPairs) : <span>
                      <Chip classes={{ root: classes.filter }}
                          label={
                            <div>
                              <strong>{t('Everything')}</strong>
                            </div>
                          }
                      />
                    </span>}
              </div>
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
                <b>{node.last_deleted_count}</b> @ {nsdt(node.last_execution_date)}
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
      last_deleted_count
      filters
    }
  `,
});

export const RetentionLine = compose(
  inject18n,
  withStyles(styles),
)(RetentionLineFragment);

class RetentionDummyComponent extends Component {
  render() {
    const { classes, dataColumns } = this.props;
    return (
      <ListItem classes={{ root: classes.item }} divider={true}>
        <ListItemIcon classes={{ root: classes.itemIcon }}>
          <Skeleton animation="wave" variant="circle" width={30} height={30} />
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
                  variant="rect"
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
                  variant="rect"
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
                  variant="rect"
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
                    variant="rect"
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

export const RetentionLineDummy = compose(
  inject18n,
  withStyles(styles),
)(RetentionDummyComponent);
