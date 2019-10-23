import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import {
  ascend, compose, descend, prop, sortWith,
} from 'ramda';
import { interval } from 'rxjs';
import graphql from 'babel-plugin-relay/macro';
import { withStyles } from '@material-ui/core/styles/index';
import Card from '@material-ui/core/Card';
import CardHeader from '@material-ui/core/CardHeader';
import CardContent from '@material-ui/core/CardContent';
import { createRefetchContainer } from 'react-relay';
import { ArrowDropDown, ArrowDropUp, Extension } from '@material-ui/icons';
import ListItem from '@material-ui/core/ListItem';
import ListItemIcon from '@material-ui/core/ListItemIcon';
import ListItemText from '@material-ui/core/ListItemText';
import List from '@material-ui/core/List';
import Chip from '@material-ui/core/Chip';
import { FIVE_SECONDS } from '../../../utils/Time';
import inject18n from '../../../components/i18n';

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
    right: 10,
    marginRight: 0,
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
  chip: {
    fontSize: 12,
    height: 20,
    float: 'left',
    marginRight: 7,
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
    width: '25%',
    fontSize: 12,
    fontWeight: '700',
  },
  active: {
    float: 'left',
    width: '10%',
    fontSize: 12,
    fontWeight: '700',
  },
  connector_type: {
    float: 'left',
    width: '15%',
    fontSize: 12,
    fontWeight: '700',
  },
  connector_scope: {
    float: 'left',
    width: '40%',
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
    width: '25%',
    height: 20,
    whiteSpace: 'nowrap',
    overflow: 'hidden',
    textOverflow: 'ellipsis',
  },
  active: {
    float: 'left',
    width: '10%',
    height: 20,
    whiteSpace: 'nowrap',
    overflow: 'hidden',
    textOverflow: 'ellipsis',
  },
  connector_type: {
    float: 'left',
    width: '15%',
    height: 20,
    whiteSpace: 'nowrap',
    overflow: 'hidden',
    textOverflow: 'ellipsis',
  },
  connector_scope: {
    float: 'left',
    width: '40%',
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
    const {
      classes, t, nsdt, data,
    } = this.props;
    const sort = sortWith(
      this.state.orderAsc
        ? [ascend(prop(this.state.sortBy))]
        : [descend(prop(this.state.sortBy))],
    );
    const sortedConnectors = sort(data.connectors);
    return (
      <Card
        raised={true}
        classes={{ root: classes.card }}
        style={{ maxHeight: '100vh', height: '100%' }}
      >
        <CardHeader
          avatar={<Extension className={classes.icon} />}
          title={t('Registered connectors')}
          style={{ paddingBottom: 0 }}
        />
        <CardContent style={{ paddingTop: 0, height: '100%' }}>
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
                    {this.SortHeader('active', 'Status', true)}
                    {this.SortHeader('connector_type', 'Type', true)}
                    {this.SortHeader('connector_scope', 'Scope', true)}
                    {this.SortHeader('updated_at', 'Last seen', true)}
                  </div>
                }
              />
            </ListItem>
            {sortedConnectors.map((connector) => (
              <ListItem
                key={connector.id}
                classes={{ root: classes.item }}
                divider={true}
                button={true}
              >
                <ListItemIcon
                  style={{
                    color: connector.active ? '#4caf50' : '#f44336',
                  }}
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
                        style={inlineStyles.active}
                      >
                        {connector.active ? t('Connected') : t('Disconnected')}
                      </div>
                      <div
                        className={classes.bodyItem}
                        style={inlineStyles.connector_type}
                      >
                        {connector.connector_type}
                      </div>
                      <div
                        className={classes.bodyItem}
                        style={inlineStyles.connector_scope}
                      >
                        {connector.connector_scope.map((scope) => (
                          <Chip
                            key={scope}
                            classes={{ root: classes.chip }}
                            label={scope}
                          />
                        ))}
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
  nsdt: PropTypes.func,
  data: PropTypes.object,
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
          connector_type
          connector_scope
          updated_at
        }
      }
    `,
  },
  connectorsStatusQuery,
);

export default compose(
  inject18n,
  withStyles(styles),
)(ConnectorsStatus);
