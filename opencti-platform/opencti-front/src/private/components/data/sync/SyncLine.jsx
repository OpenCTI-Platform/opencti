import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import { graphql, createFragmentContainer } from 'react-relay';
import { styled } from '@mui/material/styles';
import ListItem from '@mui/material/ListItem';
import { ListItemButton } from '@mui/material';
import ListItemIcon from '@mui/material/ListItemIcon';
import ListItemText from '@mui/material/ListItemText';
import { Chip } from '@filigran/design-system';
import { MoreVert } from '@mui/icons-material';
import { DatabaseImportOutline } from 'mdi-material-ui';
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

const BodyItem = styled('div')({
  display: 'flex',
  alignItems: 'center',
  height: 25,
  fontSize: 13,
  float: 'left',
  whiteSpace: 'nowrap',
  overflow: 'hidden',
  textOverflow: 'ellipsis',
  paddingRight: 10,
});

const ProducerItem = styled('div')({
  height: 40,
  display: 'flex',
  alignItems: 'center',
  float: 'left',
  paddingRight: 10,
  gap: 8,
});

const itemSx = {
  paddingLeft: '10px',
  height: 50,
};

const itemIconSx = {
  color: 'primary.main',
};

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
      return { label: t('No data'), severity: 'neutral' };
    }
    const ONE_HOUR = 3600;
    const ONE_DAY = 86400;
    const { estimatedOutOfDepth } = metrics;
    if (estimatedOutOfDepth > 0 && estimatedOutOfDepth < ONE_HOUR) {
      return { label: t('At risk'), severity: 'critical' };
    }
    if (estimatedOutOfDepth >= ONE_HOUR && estimatedOutOfDepth < ONE_DAY) {
      return { label: t('Degraded'), severity: 'high' };
    }
    return { label: t('Healthy'), severity: 'low' };
  }

  render() {
    const { node, dataColumns, paginationOptions, t, ftdt, n } = this.props;
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
            sx={itemSx}
            onClick={this.handleOpenConsumers.bind(this)}
          >
            <ListItemIcon sx={itemIconSx}>
              <DatabaseImportOutline />
            </ListItemIcon>
            <ListItemText
              primary={(
                <>
                  <BodyItem
                    style={{ width: dataColumns.name.width }}
                  >
                    {node.name}
                  </BodyItem>
                  <BodyItem
                    style={{ width: dataColumns.uri.width }}
                  >
                    {node.uri}
                  </BodyItem>
                  <BodyItem
                    style={{ width: dataColumns.messages.width }}
                  >
                    {n(node.queue_messages)}
                  </BodyItem>
                  <BodyItem
                    style={{ width: dataColumns.running.width }}
                  >
                    <ItemBoolean
                      variant="inList"
                      label={node.running ? t('Active') : t('Inactive')}
                      status={node.running}
                    />
                  </BodyItem>
                  <BodyItem
                    style={{ width: dataColumns.current_state_date.width }}
                  >
                    {ftdt(node.current_state_date)}
                  </BodyItem>
                  <ProducerItem
                    style={{ width: dataColumns.producer.width }}
                  >
                    {!health.hexColor
                      ? <span style={{ color: '#9e9e9e' }}>-</span>
                      : (
                          <Chip
                            label={health.label}
                            severity={health.severity}
                          />
                        )}
                  </ProducerItem>
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
  ftd: PropTypes.func,
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

export const SyncLine = inject18n(SyncLineFragment);

class SyncDummyComponent extends Component {
  render() {
    const { dataColumns } = this.props;
    return (
      <ListItem
        sx={itemSx}
        divider={true}
        secondaryAction={
          <MoreVert />
        }
      >
        <ListItemIcon sx={itemIconSx}>
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
              <BodyItem
                style={{ width: dataColumns.name.width }}
              >
                <Skeleton
                  animation="wave"
                  variant="rectangular"
                  width="90%"
                  height="100%"
                />
              </BodyItem>
              <BodyItem
                style={{ width: dataColumns.uri.width }}
              >
                <Skeleton
                  animation="wave"
                  variant="rectangular"
                  width="90%"
                  height="100%"
                />
              </BodyItem>
              <BodyItem
                style={{ width: dataColumns.messages.width }}
              >
                <Skeleton
                  animation="wave"
                  variant="rectangular"
                  width="90%"
                  height="100%"
                />
              </BodyItem>
              <BodyItem
                style={{ width: dataColumns.running.width }}
              >
                <Skeleton
                  animation="wave"
                  variant="rectangular"
                  width="90%"
                  height="100%"
                />
              </BodyItem>
              <BodyItem
                style={{ width: dataColumns.current_state_date.width }}
              >
                <Skeleton
                  animation="wave"
                  variant="rectangular"
                  width={100}
                  height="100%"
                />
              </BodyItem>
              <BodyItem
                style={{ width: dataColumns.producer.width }}
              >
                <Skeleton
                  animation="wave"
                  variant="rectangular"
                  width="90%"
                  height="100%"
                />
              </BodyItem>
            </div>
          )}
        />
      </ListItem>
    );
  }
}

SyncDummyComponent.propTypes = {
  dataColumns: PropTypes.object,
};

export const SyncLineDummy = inject18n(SyncDummyComponent);
