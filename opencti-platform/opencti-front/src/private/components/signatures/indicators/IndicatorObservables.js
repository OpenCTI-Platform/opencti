import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import {
  compose, map, sortWith, ascend, descend, prop, assoc,
} from 'ramda';
import graphql from 'babel-plugin-relay/macro';
import { createFragmentContainer } from 'react-relay';
import { Link } from 'react-router-dom';
import { withStyles } from '@material-ui/core/styles';
import List from '@material-ui/core/List';
import ListItem from '@material-ui/core/ListItem';
import ListItemIcon from '@material-ui/core/ListItemIcon';
import ListItemText from '@material-ui/core/ListItemText';
import ListItemSecondaryAction from '@material-ui/core/ListItemSecondaryAction';
import { ArrowDropDown, ArrowDropUp } from '@material-ui/icons';
import inject18n from '../../../../components/i18n';
import ItemIcon from '../../../../components/ItemIcon';
import IndicatorHeader from './IndicatorHeader';
import IndicatorAddObservableRefs from './IndicatorAddObservableRefs';
import IndicatorRefPopover from './IndicatorRefPopover';

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
});

const inlineStylesHeaders = {
  iconSort: {
    position: 'absolute',
    margin: '0 0 0 5px',
    padding: 0,
    top: '0px',
  },
  entity_type: {
    float: 'left',
    width: '20%',
    fontSize: 12,
    fontWeight: '700',
  },
  observable_value: {
    float: 'left',
    width: '50%',
    fontSize: 12,
    fontWeight: '700',
  },
  created_at: {
    float: 'left',
    fontSize: 12,
    fontWeight: '700',
  },
};

const inlineStyles = {
  entity_type: {
    float: 'left',
    width: '20%',
    height: 20,
    whiteSpace: 'nowrap',
    overflow: 'hidden',
    textOverflow: 'ellipsis',
  },
  observable_value: {
    float: 'left',
    width: '50%',
    height: 20,
    whiteSpace: 'nowrap',
    overflow: 'hidden',
    textOverflow: 'ellipsis',
  },
  created_at: {
    float: 'left',
    height: 20,
    whiteSpace: 'nowrap',
    overflow: 'hidden',
    textOverflow: 'ellipsis',
  },
};

class IndicatorObservablesComponent extends Component {
  constructor(props) {
    super(props);
    this.state = { sortBy: 'name', orderAsc: false };
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
      t, fd, classes, indicator,
    } = this.props;
    const observableRefs = map(
      (n) => assoc('relation', n.relation, n.node),
      indicator.observableRefs.edges,
    );
    const sort = sortWith(
      this.state.orderAsc
        ? [ascend(prop(this.state.sortBy))]
        : [descend(prop(this.state.sortBy))],
    );
    const sortedObservableRefs = sort(observableRefs);
    return (
      <div>
        <IndicatorHeader indicator={indicator} />
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
                  {this.SortHeader('entity_type', 'Type', true)}
                  {this.SortHeader('observable_value', 'Value', true)}
                  {this.SortHeader('created_at', 'Creation date', true)}
                </div>
              }
            />
            <ListItemSecondaryAction>&nbsp;</ListItemSecondaryAction>
          </ListItem>
          {sortedObservableRefs.map((observableRef) => (
            <ListItem
              key={observableRef.id}
              classes={{ root: classes.item }}
              divider={true}
              button={true}
              component={Link}
              to={`/dashboard/signatures/observables/${observableRef.id}`}
            >
              <ListItemIcon classes={{ root: classes.itemIcon }}>
                <ItemIcon type={observableRef.entity_type} />
              </ListItemIcon>
              <ListItemText
                primary={
                  <div>
                    <div
                      className={classes.bodyItem}
                      style={inlineStyles.entity_type}
                    >
                      {t(`observable_${observableRef.entity_type}`)}
                    </div>
                    <div
                      className={classes.bodyItem}
                      style={inlineStyles.observable_value}
                    >
                      {observableRef.observable_value}
                    </div>
                    <div
                      className={classes.bodyItem}
                      style={inlineStyles.created_at}
                    >
                      {fd(observableRef.created_at)}
                    </div>
                  </div>
                }
              />
              <ListItemSecondaryAction>
                <IndicatorRefPopover
                  indicatorId={indicator.id}
                  entityId={observableRef.id}
                  relationId={observableRef.relation.id}
                />
              </ListItemSecondaryAction>
            </ListItem>
          ))}
        </List>
        <IndicatorAddObservableRefs
          indicatorId={indicator.id}
          indicatorObservableRefs={indicator.observableRefs.edges}
        />
      </div>
    );
  }
}

IndicatorObservablesComponent.propTypes = {
  indicator: PropTypes.object,
  classes: PropTypes.object,
  t: PropTypes.func,
  fd: PropTypes.func,
  history: PropTypes.object,
};

const IndicatorObservables = createFragmentContainer(
  IndicatorObservablesComponent,
  {
    indicator: graphql`
      fragment IndicatorObservables_indicator on Indicator {
        id
        observableRefs {
          edges {
            node {
              id
              entity_type
              observable_value
              created_at
              updated_at
            }
            relation {
              id
            }
          }
        }
        ...IndicatorHeader_indicator
      }
    `,
  },
);

export default compose(inject18n, withStyles(styles))(IndicatorObservables);
