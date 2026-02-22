import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import { graphql, createFragmentContainer } from 'react-relay';
import withStyles from '@mui/styles/withStyles';
import ListItem from '@mui/material/ListItem';
import { ListItemButton } from '@mui/material';
import ListItemIcon from '@mui/material/ListItemIcon';
import ListItemText from '@mui/material/ListItemText';
import Chip from '@mui/material/Chip';
import { MoreVert } from '@mui/icons-material';
import { DatabaseImportOutline } from 'mdi-material-ui';
import { compose } from 'ramda';
import Slide from '@mui/material/Slide';
import Skeleton from '@mui/material/Skeleton';
import SyncPopover from './SyncPopover';
import SyncConsumersDrawer from './SyncConsumersDrawer';
import inject18n from '../../../../components/i18n';
import ItemBoolean from '../../../../components/ItemBoolean';
import Security from '../../../../utils/Security';
import { INGESTION_SETINGESTIONS } from '../../../../utils/hooks/useGranted';

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
    display: 'flex',
    alignItems: 'center',
    height: 25,
    fontSize: 13,
    float: 'left',
    whiteSpace: 'nowrap',
    overflow: 'hidden',
    textOverflow: 'ellipsis',
    paddingRight: 10,
  },
  producerItem: {
    height: 40,
    display: 'flex',
    alignItems: 'center',
    float: 'left',
    paddingRight: 10,
    gap: 8,
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

class SyncLineLineComponent extends Component {
  constructor(props) {
    super(props);
    this.state = {
      displayConsumers: false,
    };
  }

  handleOpenConsumers() {
    this.setState({ displayConsumers: true });
  }

  handleCloseConsumers() {
    this.setState({ displayConsumers: false });
  }

  computeConsumerHealth() {
    const { node, t } = this.props;
    const metrics = node.consumer_metrics;
    if (!metrics) {
      return { label: t('No data'), hexColor: null };
    }
    const ONE_HOUR = 3600;
    const ONE_DAY = 86400;
    const { estimatedOutOfDepth } = metrics;
    if (estimatedOutOfDepth > 0 && estimatedOutOfDepth < ONE_HOUR) {
      return { label: t('At risk'), hexColor: '#c62828' };
    }
    if (estimatedOutOfDepth >= ONE_HOUR && estimatedOutOfDepth < ONE_DAY) {
      return { label: t('Degraded'), hexColor: '#d84315' };
    }
    return { label: t('Healthy'), hexColor: '#2e7d32' };
  }

  render() {
    const { classes, node, dataColumns, paginationOptions, t, nsdt, n } = this.props;
    const health = this.computeConsumerHealth();
    return (
      <>
        <ListItem
          divider={true}
          disablePadding
          secondaryAction={(
            <Security needs={[INGESTION_SETINGESTIONS]}>
              <SyncPopover
                syncId={node.id}
                paginationOptions={paginationOptions}
                running={node.running}
              />
            </Security>
          )}
        >
          <ListItemButton
            classes={{ root: classes.item }}
            onClick={this.handleOpenConsumers.bind(this)}
          >
            <ListItemIcon classes={{ root: classes.itemIcon }}>
              <DatabaseImportOutline />
            </ListItemIcon>
            <ListItemText
              primary={(
                <>
                  <div
                    className={classes.bodyItem}
                    style={{ width: dataColumns.name.width }}
                  >
                    {node.name}
                  </div>
                  <div
                    className={classes.bodyItem}
                    style={{ width: dataColumns.uri.width }}
                  >
                    {node.uri}
                  </div>
                  <div
                    className={classes.bodyItem}
                    style={{ width: dataColumns.messages.width }}
                  >
                    {n(node.queue_messages)}
                  </div>
                  <div
                    className={classes.bodyItem}
                    style={{ width: dataColumns.running.width }}
                  >
                    <ItemBoolean
                      variant="inList"
                      label={node.running ? t('Active') : t('Inactive')}
                      status={node.running}
                    />
                  </div>
                  <div
                    className={classes.bodyItem}
                    style={{ width: dataColumns.current_state_date.width }}
                  >
                    {nsdt(node.current_state_date)}
                  </div>
                  <div
                    className={classes.producerItem}
                    style={{ width: dataColumns.producer.width }}
                  >
                    {!health.hexColor
                      ? <span style={{ color: '#9e9e9e' }}>-</span>
                      : (
                          <Chip
                            label={health.label}
                            style={{
                              fontSize: 12,
                              lineHeight: '12px',
                              borderRadius: 4,
                              height: 20,
                              backgroundColor: `${health.hexColor}33`,
                              color: health.hexColor,
                              border: `2px solid ${health.hexColor}`,
                            }}
                          />
                        )}
                  </div>
                </>
              )}
            />
          </ListItemButton>
        </ListItem>
        <SyncConsumersDrawer
          syncId={node.id}
          syncName={node.name}
          open={this.state.displayConsumers}
          onClose={this.handleCloseConsumers.bind(this)}
        />
      </>
    );
  }
}

SyncLineLineComponent.propTypes = {
  dataColumns: PropTypes.object,
  node: PropTypes.object,
  paginationOptions: PropTypes.object,
  me: PropTypes.object,
  classes: PropTypes.object,
  fd: PropTypes.func,
};

const SyncLineFragment = createFragmentContainer(SyncLineLineComponent, {
  node: graphql`
    fragment SyncLine_node on Synchronizer {
      id
      name
      uri
      stream_id
      running
      current_state_date
      queue_messages
      ssl_verify
      consumer_metrics {
        connectionId
        estimatedOutOfDepth
      }
    }
  `,
});

export const SyncLine = compose(
  inject18n,
  withStyles(styles),
)(SyncLineFragment);

class SyncDummyComponent extends Component {
  render() {
    const { classes, dataColumns } = this.props;
    return (
      <ListItem
        classes={{ root: classes.item }}
        divider={true}
        secondaryAction={
          <MoreVert classes={classes.itemIconDisabled} />
        }
      >
        <ListItemIcon classes={{ root: classes.itemIcon }}>
          <Skeleton
            animation="wave"
            variant="circular"
            width={30}
            height={30}
          />
        </ListItemIcon>
        <ListItemText
          primary={(
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
                style={{ width: dataColumns.uri.width }}
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
                style={{ width: dataColumns.messages.width }}
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
                style={{ width: dataColumns.running.width }}
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
                style={{ width: dataColumns.current_state_date.width }}
              >
                <Skeleton
                  animation="wave"
                  variant="rectangular"
                  width={100}
                  height="100%"
                />
              </div>
              <div
                className={classes.bodyItem}
                style={{ width: dataColumns.producer.width }}
              >
                <Skeleton
                  animation="wave"
                  variant="rectangular"
                  width="90%"
                  height="100%"
                />
              </div>
            </div>
          )}
        />
      </ListItem>
    );
  }
}

SyncDummyComponent.propTypes = {
  dataColumns: PropTypes.object,
  classes: PropTypes.object,
};

export const SyncLineDummy = compose(
  inject18n,
  withStyles(styles),
)(SyncDummyComponent);
