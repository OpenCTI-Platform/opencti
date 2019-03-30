/* eslint-disable no-nested-ternary */
// TODO Remove no-nested-ternary
import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import {
  compose,
  map,
  sortWith,
  ascend,
  descend,
  prop,
  groupBy,
  pipe,
  values,
  head,
} from 'ramda';
import graphql from 'babel-plugin-relay/macro';
import { createFragmentContainer } from 'react-relay';
import { Link } from 'react-router-dom';
import { withStyles } from '@material-ui/core/styles';
import List from '@material-ui/core/List';
import ListItem from '@material-ui/core/ListItem';
import ListItemIcon from '@material-ui/core/ListItemIcon';
import ListItemText from '@material-ui/core/ListItemText';
import {
  ArrowDropDown,
  ArrowDropUp,
  KeyboardArrowRight,
} from '@material-ui/icons';
import inject18n from '../../../components/i18n';
import ItemIcon from '../../../components/ItemIcon';
import ReportHeader from './ReportHeader';
import ReportAddObservable from './ReportAddObservable';
import { dateFormat } from '../../../utils/Time';

const styles = theme => ({
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
    transition: 'background-color 0.1s ease',
    cursor: 'pointer',
    '&:hover': {
      background: 'rgba(0, 0, 0, 0.1)',
    },
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
    margin: '-3px 0 0 5px',
    padding: 0,
    top: '0px',
  },
  type: {
    float: 'left',
    width: '15%',
    fontSize: 12,
    fontWeight: '700',
  },
  observable_value: {
    float: 'left',
    width: '20%',
    fontSize: 12,
    fontWeight: '700',
  },
  threats: {
    float: 'left',
    width: '20%',
    fontSize: 12,
    fontWeight: '700',
  },
  first_seen: {
    float: 'left',
    width: '15%',
    fontSize: 12,
    fontWeight: '700',
  },
  last_seen: {
    float: 'left',
    width: '15%',
    fontSize: 12,
    fontWeight: '700',
  },
  weight: {
    float: 'left',
    fontSize: 12,
    fontWeight: '700',
  },
};

const inlineStyles = {
  type: {
    float: 'left',
    width: '15%',
    height: 20,
    whiteSpace: 'nowrap',
    overflow: 'hidden',
    textOverflow: 'ellipsis',
  },
  observable_value: {
    float: 'left',
    width: '20%',
    height: 20,
    whiteSpace: 'nowrap',
    overflow: 'hidden',
    textOverflow: 'ellipsis',
  },
  threats: {
    float: 'left',
    width: '20%',
    height: 20,
    whiteSpace: 'nowrap',
    overflow: 'hidden',
    textOverflow: 'ellipsis',
  },
  first_seen: {
    float: 'left',
    width: '15%',
    height: 20,
    whiteSpace: 'nowrap',
    overflow: 'hidden',
    textOverflow: 'ellipsis',
  },
  last_seen: {
    float: 'left',
    width: '15%',
    height: 20,
    whiteSpace: 'nowrap',
    overflow: 'hidden',
    textOverflow: 'ellipsis',
  },
  weight: {
    float: 'left',
    height: 20,
    whiteSpace: 'nowrap',
    overflow: 'hidden',
    textOverflow: 'ellipsis',
  },
};

class ReportObservablesComponent extends Component {
  constructor(props) {
    super(props);
    this.state = { sortBy: 'name', orderAsc: false };
  }

  reverseBy(field) {
    this.setState({ sortBy: field, orderAsc: !this.state.orderAsc });
  }

  SortHeader(field, label, isSortable) {
    const { t } = this.props;
    if (isSortable) {
      return (
        <div
          style={inlineStylesHeaders[field]}
          onClick={this.reverseBy.bind(this, field)}
        >
          <span>{t(label)}</span>
          {this.state.sortBy === field ? (
            this.state.orderAsc ? (
              <ArrowDropDown style={inlineStylesHeaders.iconSort} />
            ) : (
              <ArrowDropUp style={inlineStylesHeaders.iconSort} />
            )
          ) : (
            ''
          )}
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
    const relationRefs = pipe(
      map(n => n.node),
      groupBy(prop('id')),
      values,
      map(n => head(n)),
    )(report.relationRefs.edges);
    console.log(relationRefs);
    const sort = sortWith(
      this.state.orderAsc
        ? [ascend(prop(this.state.sortBy))]
        : [descend(prop(this.state.sortBy))],
    );
    const sortedRelationRefs = sort(relationRefs);
    return (
      <div>
        <ReportHeader report={report} />
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
                  {this.SortHeader('type', 'Type', true)}
                  {this.SortHeader(
                    'observable_value',
                    'Observable value',
                    true,
                  )}
                  {this.SortHeader('threats', 'Linked threat(s)', true)}
                  {this.SortHeader('first_seen', 'First seen', true)}
                  {this.SortHeader('last_seen', 'Last seen', true)}
                  {this.SortHeader('weight', 'Confidence level', true)}
                </div>
              }
            />
          </ListItem>
          {sortedRelationRefs.map((relationRef) => {
            const link = '/dashboard/observables';
            return (
              <ListItem
                key={relationRef.id}
                classes={{ root: classes.item }}
                divider={true}
                component={Link}
                to={`${link}/${relationRef.id}`}
              >
                <ListItemIcon classes={{ root: classes.itemIcon }}>
                  <ItemIcon type={relationRef.type} />
                </ListItemIcon>
                <ListItemText
                  primary={
                    <div>
                      <div
                        className={classes.bodyItem}
                        style={inlineStyles.type}
                      >
                        {t(`observable_${relationRef.type}`)}
                      </div>
                      <div
                        className={classes.bodyItem}
                        style={inlineStyles.observable_value}
                      >
                        {relationRef.observable_value}
                      </div>
                      <div
                        className={classes.bodyItem}
                        style={inlineStyles.threats}
                      >
                        {relationRef.threats}
                      </div>
                      <div
                        className={classes.bodyItem}
                        style={inlineStyles.first_seen}
                      >
                        {fd(relationRef.first_seen)}
                      </div>
                      <div
                        className={classes.bodyItem}
                        style={inlineStyles.last_seen}
                      >
                        {fd(relationRef.last_seen)}
                      </div>
                    </div>
                  }
                />
                <ListItemIcon classes={{ root: classes.goIcon }}>
                  <KeyboardArrowRight />
                </ListItemIcon>
              </ListItem>
            );
          })}
        </List>
        <ReportAddObservable
          reportId={report.id}
          firstSeen={dateFormat(report.published)}
          lastSeen={dateFormat(report.published)}
          weight={report.source_confidence_level}
        />
      </div>
    );
  }
}

ReportObservablesComponent.propTypes = {
  report: PropTypes.object,
  classes: PropTypes.object,
  t: PropTypes.func,
  fd: PropTypes.func,
  history: PropTypes.object,
};

const ReportObservables = createFragmentContainer(ReportObservablesComponent, {
  report: graphql`
    fragment ReportObservables_report on Report {
      id
      published
      source_confidence_level
      relationRefs(relationType: $relationType) {
        edges {
          node {
            id
            type
            name
            first_seen
            last_seen
            created_at
            updated_at
            from {
              id
              type
              name
              ... on StixObservable {
                observable_value
              }
            }
            to {
              id
              type
              name
              ... on StixObservable {
                observable_value
              }
            }
          }
        }
      }
      ...ReportHeader_report
    }
  `,
});

export default compose(
  inject18n,
  withStyles(styles),
)(ReportObservables);
