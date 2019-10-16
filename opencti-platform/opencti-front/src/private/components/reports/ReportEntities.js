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
import { resolveLink } from '../../../utils/Entity';
import inject18n from '../../../components/i18n';
import ItemIcon from '../../../components/ItemIcon';
import ReportHeader from './ReportHeader';
import ReportAddObjectRefs from './ReportAddObjectRefs';
import ReportRefPopover from './ReportRefPopover';

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
  name: {
    float: 'left',
    width: '40%',
    fontSize: 12,
    fontWeight: '700',
  },
  entity_type: {
    float: 'left',
    width: '20%',
    fontSize: 12,
    fontWeight: '700',
  },
  created_at: {
    float: 'left',
    width: '15%',
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
    width: '40%',
    height: 20,
    whiteSpace: 'nowrap',
    overflow: 'hidden',
    textOverflow: 'ellipsis',
  },
  entity_type: {
    float: 'left',
    width: '20%',
    height: 20,
    whiteSpace: 'nowrap',
    overflow: 'hidden',
    textOverflow: 'ellipsis',
  },
  created_at: {
    float: 'left',
    width: '15%',
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

class ReportEntitiesComponent extends Component {
  constructor(props) {
    super(props);
    this.state = { sortBy: 'name', orderAsc: false };
  }

  reverseBy(field) {
    this.setState({ sortBy: field, orderAsc: !this.state.orderAsc });
  }

  SortHeader(field, label, isSortable) {
    const { t } = this.props;
    const sortComponent = this.state.orderAsc
      ? <ArrowDropDown style={inlineStylesHeaders.iconSort} />
      : <ArrowDropUp style={inlineStylesHeaders.iconSort} />;
    if (isSortable) {
      return (
        <div
          style={inlineStylesHeaders[field]}
          onClick={this.reverseBy.bind(this, field)}>
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
    const objectRefs = map(
      n => assoc('relation', n.relation, n.node),
      report.objectRefs.edges,
    );
    const sort = sortWith(
      this.state.orderAsc
        ? [ascend(prop(this.state.sortBy))]
        : [descend(prop(this.state.sortBy))],
    );
    const sortedObjectRefs = sort(objectRefs);
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
                  {this.SortHeader('name', 'Name', true)}
                  {this.SortHeader('entity_type', 'Entity type', true)}
                  {this.SortHeader('created_at', 'Creation date', true)}
                  {this.SortHeader('updated_at', 'Modification date', true)}
                </div>
              }
            />
            <ListItemSecondaryAction>&nbsp;</ListItemSecondaryAction>
          </ListItem>
          {sortedObjectRefs.map((objectRef) => {
            const link = resolveLink(objectRef.entity_type);
            return (
              <ListItem
                key={objectRef.id}
                classes={{ root: classes.item }}
                divider={true}
                button={true}
                component={Link}
                to={`${link}/${objectRef.id}`}
              >
                <ListItemIcon classes={{ root: classes.itemIcon }}>
                  <ItemIcon type={objectRef.entity_type} />
                </ListItemIcon>
                <ListItemText
                  primary={
                    <div>
                      <div
                        className={classes.bodyItem}
                        style={inlineStyles.name}
                      >
                        {objectRef.name}
                      </div>
                      <div
                        className={classes.bodyItem}
                        style={inlineStyles.entity_type}
                      >
                        {t(`entity_${objectRef.entity_type}`)}
                      </div>
                      <div
                        className={classes.bodyItem}
                        style={inlineStyles.created_at}
                      >
                        {fd(objectRef.created_at)}
                      </div>
                      <div
                        className={classes.bodyItem}
                        style={inlineStyles.updated_at}
                      >
                        {fd(objectRef.updated_at)}
                      </div>
                    </div>
                  }
                />
                <ListItemSecondaryAction>
                  <ReportRefPopover
                    reportId={report.id}
                    relationId={objectRef.relation.id}
                  />
                </ListItemSecondaryAction>
              </ListItem>
            );
          })}
        </List>
        <ReportAddObjectRefs
          reportId={report.id}
          reportObjectRefs={report.objectRefs.edges}
        />
      </div>
    );
  }
}

ReportEntitiesComponent.propTypes = {
  report: PropTypes.object,
  classes: PropTypes.object,
  t: PropTypes.func,
  fd: PropTypes.func,
  history: PropTypes.object,
};

const ReportEntities = createFragmentContainer(ReportEntitiesComponent, {
  report: graphql`
    fragment ReportEntities_report on Report {
      id
      objectRefs {
        edges {
          node {
            id
            entity_type
            name
            created_at
            updated_at
          }
          relation {
            id
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
)(ReportEntities);
