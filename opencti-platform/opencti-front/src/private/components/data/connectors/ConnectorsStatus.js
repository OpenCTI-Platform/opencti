import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import {
  ascend,
  compose,
  descend,
  prop,
  sortWith,
  map,
  assoc,
  filter,
  propOr,
} from 'ramda';
import { interval } from 'rxjs';
import withStyles from '@mui/styles/withStyles';
import Card from '@mui/material/Card';
import CardHeader from '@mui/material/CardHeader';
import CardContent from '@mui/material/CardContent';
import { graphql, createRefetchContainer } from 'react-relay';
import { ArrowDropDown, ArrowDropUp, Extension } from '@mui/icons-material';
import ListItem from '@mui/material/ListItem';
import ListItemIcon from '@mui/material/ListItemIcon';
import ListItemText from '@mui/material/ListItemText';
import ListItemSecondaryAction from '@mui/material/ListItemSecondaryAction';
import List from '@mui/material/List';
import Tooltip from '@mui/material/Tooltip';
import { LayersRemove, Delete } from 'mdi-material-ui';
import IconButton from '@mui/material/IconButton';
import { Link, withRouter } from 'react-router-dom';
import { FIVE_SECONDS } from '../../../../utils/Time';
import inject18n from '../../../../components/i18n';
import { commitMutation, MESSAGING$ } from '../../../../relay/environment';
import Security, { MODULES_MODMANAGE } from '../../../../utils/Security';
import {
  connectorDeletionMutation,
  connectorResetStateMutation,
} from './Connector';
import ItemBoolean from '../../../../components/ItemBoolean';

const interval$ = interval(FIVE_SECONDS);

const styles = (theme) => ({
  linesContainer: {
    marginTop: 10,
  },
  itemHead: {
    paddingLeft: 10,
    textTransform: 'uppercase',
    cursor: 'pointer',
  },
  item: {
    paddingLeft: 10,
    height: 50,
  },
  bodyItem: {
    height: '100%',
    fontSize: 13,
  },
  itemIcon: {
    color: theme.palette.primary.main,
  },
  goIcon: {
    position: 'absolute',
    right: -10,
  },
  inputLabel: {
    float: 'left',
  },
  sortIcon: {
    float: 'left',
    margin: '-5px 0 0 15px',
  },
  icon: {
    color: theme.palette.primary.main,
  },
});

const inlineStylesHeaders = {
  iconSort: {
    position: 'absolute',
    margin: '0 0 0 5px',
    padding: 0,
    top: '0px',
  },
  name: {
    float: 'left',
    width: '35%',
    fontSize: 12,
    fontWeight: '700',
  },
  connector_type: {
    float: 'left',
    width: '20%',
    fontSize: 12,
    fontWeight: '700',
  },
  auto: {
    float: 'left',
    width: '20%',
    fontSize: 12,
    fontWeight: '700',
  },
  messages: {
    float: 'left',
    width: '10%',
    fontSize: 12,
    fontWeight: '700',
  },
  updated_at: {
    float: 'left',
    fontSize: 12,
    fontWeight: '700',
  },
};

const inlineStyles = {
  name: {
    float: 'left',
    width: '35%',
    height: 20,
    whiteSpace: 'nowrap',
    overflow: 'hidden',
    textOverflow: 'ellipsis',
  },
  connector_type: {
    float: 'left',
    width: '20%',
    height: 20,
    whiteSpace: 'nowrap',
    overflow: 'hidden',
    textOverflow: 'ellipsis',
  },
  auto: {
    float: 'left',
    width: '20%',
    height: 20,
    whiteSpace: 'nowrap',
    overflow: 'hidden',
    textOverflow: 'ellipsis',
  },
  messages: {
    float: 'left',
    width: '10%',
    height: 20,
    whiteSpace: 'nowrap',
    overflow: 'hidden',
    textOverflow: 'ellipsis',
  },
  updated_at: {
    float: 'left',
    height: 20,
    whiteSpace: 'nowrap',
    overflow: 'hidden',
    textOverflow: 'ellipsis',
  },
};

class ConnectorsStatusComponent extends Component {
  constructor(props) {
    super(props);
    this.state = { sortBy: 'name', orderAsc: true };
  }

  componentDidMount() {
    this.subscription = interval$.subscribe(() => {
      this.props.relay.refetch();
    });
  }

  componentWillUnmount() {
    this.subscription.unsubscribe();
  }

  // eslint-disable-next-line class-methods-use-this
  handleResetState(connectorId) {
    commitMutation({
      mutation: connectorResetStateMutation,
      variables: {
        id: connectorId,
      },
      onCompleted: () => {
        MESSAGING$.notifySuccess('The connector state has been reset');
      },
    });
  }

  handleDelete(connectorId) {
    commitMutation({
      mutation: connectorDeletionMutation,
      variables: {
        id: connectorId,
      },
      onCompleted: () => {
        MESSAGING$.notifySuccess('The connector has been cleared');
        this.props.history.push('/dashboard/data/connectors');
      },
    });
  }

  reverseBy(field) {
    this.setState({ sortBy: field, orderAsc: !this.state.orderAsc });
  }

  SortHeader(field, label, isSortable) {
    const { t } = this.props;
    const sortComponent = this.state.orderAsc ? (
      <ArrowDropDown style={inlineStylesHeaders.iconSort} />
    ) : (
      <ArrowDropUp style={inlineStylesHeaders.iconSort} />
    );
    if (isSortable) {
      return (
        <div
          style={inlineStylesHeaders[field]}
          onClick={this.reverseBy.bind(this, field)}
        >
          <span>{t(label)}</span>
          {this.state.sortBy === field ? sortComponent : ''}
        </div>
      );
    }
    return (
      <div style={inlineStylesHeaders[field]}>
        <span>{t(label)}</span>
      </div>
    );
  }

  render() {
    const { classes, t, n, nsdt, data } = this.props;
    const { queues } = data.rabbitMQMetrics;
    const connectors = map(
      (i) => assoc(
        'messages',
        propOr(
          0,
          'messages',
          filter(
            (o) => o.name
                === (i.connector_type === 'INTERNAL_ENRICHMENT'
                  ? `listen_${i.id}`
                  : `push_${i.id}`),
            queues,
          )[0],
        ),
        i,
      ),
      data.connectors,
    );
    const sort = sortWith(
      this.state.orderAsc
        ? [ascend(prop(this.state.sortBy))]
        : [descend(prop(this.state.sortBy))],
    );
    const sortedConnectors = sort(connectors);
    return (
      <Card variant="outlined">
        <CardHeader
          avatar={<Extension className={classes.icon} />}
          title={t('Registered connectors')}
          style={{ paddingBottom: 0 }}
        />
        <CardContent style={{ paddingTop: 0 }}>
          <List classes={{ root: classes.linesContainer }}>
            <ListItem
              classes={{ root: classes.itemHead }}
              divider={false}
              style={{ paddingTop: 0 }}
            >
              <ListItemIcon>
                <span
                  style={{
                    padding: '0 8px 0 8px',
                    fontWeight: 700,
                    fontSize: 12,
                  }}
                >
                  #
                </span>
              </ListItemIcon>
              <ListItemText
                primary={
                  <div>
                    {this.SortHeader('name', 'Name', true)}
                    {this.SortHeader('connector_type', 'Type', true)}
                    {this.SortHeader('auto', 'Automatic trigger', true)}
                    {this.SortHeader('messages', 'Messages', true)}
                    {this.SortHeader('updated_at', 'Modified', true)}
                  </div>
                }
              />
              <ListItemSecondaryAction> &nbsp; </ListItemSecondaryAction>
            </ListItem>
            {sortedConnectors.map((connector) => (
              <ListItem
                key={connector.id}
                classes={{ root: classes.item }}
                divider={true}
                button={true}
                component={Link}
                to={`/dashboard/data/connectors/${connector.id}`}
              >
                <ListItemIcon
                  style={{ color: connector.active ? '#4caf50' : '#f44336' }}
                >
                  <Extension />
                </ListItemIcon>
                <ListItemText
                  primary={
                    <div>
                      <div
                        className={classes.bodyItem}
                        style={inlineStyles.name}
                      >
                        {connector.name}
                      </div>
                      <div
                        className={classes.bodyItem}
                        style={inlineStyles.connector_type}
                      >
                        {t(connector.connector_type)}
                      </div>
                      <div
                        className={classes.bodyItem}
                        style={inlineStyles.auto}
                      >
                        <ItemBoolean
                          label={connector.auto ? t('Automatic') : t('Manual')}
                          status={
                            connector.connector_type
                              === 'INTERNAL_ENRICHMENT'
                            || connector.connector_type === 'INTERNAL_IMPORT_FILE'
                              ? connector.auto
                              : null
                          }
                          variant="inList"
                        />
                      </div>
                      <div
                        className={classes.bodyItem}
                        style={inlineStyles.messages}
                      >
                        {n(connector.messages)}
                      </div>
                      <div
                        className={classes.bodyItem}
                        style={inlineStyles.updated_at}
                      >
                        {nsdt(connector.updated_at)}
                      </div>
                    </div>
                  }
                />
                <ListItemSecondaryAction>
                  <Security needs={[MODULES_MODMANAGE]}>
                    <Tooltip title={t('Reset the connector state')}>
                      <IconButton
                        onClick={this.handleResetState.bind(this, connector.id)}
                        aria-haspopup="true"
                        color="primary"
                        size="large"
                      >
                        <LayersRemove />
                      </IconButton>
                    </Tooltip>
                    <Tooltip title={t('Clear this connector')}>
                      <IconButton
                        onClick={this.handleDelete.bind(this, connector.id)}
                        aria-haspopup="true"
                        color="primary"
                        disabled={connector.active}
                        size="large"
                      >
                        <Delete />
                      </IconButton>
                    </Tooltip>
                  </Security>
                </ListItemSecondaryAction>
              </ListItem>
            ))}
          </List>
        </CardContent>
      </Card>
    );
  }
}

ConnectorsStatusComponent.propTypes = {
  classes: PropTypes.object,
  t: PropTypes.func,
  n: PropTypes.func,
  nsdt: PropTypes.func,
  data: PropTypes.object,
  history: PropTypes.object,
};

export const connectorsStatusQuery = graphql`
  query ConnectorsStatusQuery {
    ...ConnectorsStatus_data
  }
`;

const ConnectorsStatus = createRefetchContainer(
  ConnectorsStatusComponent,
  {
    data: graphql`
      fragment ConnectorsStatus_data on Query {
        connectors {
          id
          name
          active
          auto
          connector_type
          connector_scope
          updated_at
          config {
            listen
            listen_exchange
            push
            push_exchange
          }
        }
        rabbitMQMetrics {
          queues {
            name
            messages
            messages_ready
            messages_unacknowledged
            consumers
            idle_since
            message_stats {
              ack
              ack_details {
                rate
              }
            }
          }
        }
      }
    `,
  },
  connectorsStatusQuery,
);

export default compose(
  inject18n,
  withRouter,
  withStyles(styles),
)(ConnectorsStatus);
