import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import {
  compose,
  map,
  sortWith,
  ascend,
  descend,
  prop,
  assoc,
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
import { HexagonOutline } from 'mdi-material-ui';
import inject18n from '../../../components/i18n';
import ReportAddObservableRefs from './ReportAddObservableRefs';
import ReportRefPopover from './ReportRefPopover';

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
    width: '15%',
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

class ReportObservablesLinesComponent extends Component {
  constructor(props) {
    super(props);
    this.state = { sortBy: 'entity_type', orderAsc: false };
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
      t, fd, classes, report,
    } = this.props;
    const observableRefs = map(
      (n) => assoc('relation', n.relation, n.node),
      report.observableRefs.edges,
    );
    const sort = sortWith(
      this.state.orderAsc
        ? [ascend(prop(this.state.sortBy))]
        : [descend(prop(this.state.sortBy))],
    );
    const sortedObservableRefs = sort(observableRefs);
    return (
      <div>
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
          {sortedObservableRefs.map((observableRef) => {
            return (
              <ListItem
                key={observableRef.id}
                classes={{ root: classes.item }}
                divider={true}
                button={true}
                component={Link}
                to={`/dashboard/signatures/observables/${observableRef.id}`}
              >
                <ListItemIcon classes={{ root: classes.itemIcon }}>
                  <HexagonOutline />
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
                        style={inlineStyles.first_seen}
                      >
                        {fd(observableRef.created_at)}
                      </div>
                    </div>
                  }
                />
                <ListItemSecondaryAction>
                  <ReportRefPopover
                    reportId={report.id}
                    entityId={observableRef.id}
                    relationId={observableRef.relation.id}
                  />
                </ListItemSecondaryAction>
              </ListItem>
            );
          })}
        </List>
        <ReportAddObservableRefs
          reportId={report.id}
          reportObservableRefs={report.observableRefs.edges}
        />
      </div>
    );
  }
}

ReportObservablesLinesComponent.propTypes = {
  report: PropTypes.object,
  classes: PropTypes.object,
  t: PropTypes.func,
  fd: PropTypes.func,
  history: PropTypes.object,
};

const ReportObservablesLines = createFragmentContainer(
  ReportObservablesLinesComponent,
  {
    report: graphql`
      fragment ReportObservablesLines_report on Report
        @argumentDefinitions(relationType: { type: "String" }) {
        id
        published
        source_confidence_level
        observableRefs {
          edges {
            node {
              id
              observable_value
              entity_type
              created_at
            }
            relation {
              id
            }
          }
        }
        ...ReportHeader_report
      }
    `,
  },
);

export default compose(
  inject18n,
  withStyles(styles),
)(ReportObservablesLines);
