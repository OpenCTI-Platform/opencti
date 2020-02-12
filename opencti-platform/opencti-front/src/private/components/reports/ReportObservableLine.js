import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import { Link } from 'react-router-dom';
import { createFragmentContainer } from 'react-relay';
import graphql from 'babel-plugin-relay/macro';
import { withStyles } from '@material-ui/core/styles';
import ListItem from '@material-ui/core/ListItem';
import ListItemIcon from '@material-ui/core/ListItemIcon';
import ListItemText from '@material-ui/core/ListItemText';
import ListItemSecondaryAction from '@material-ui/core/ListItemSecondaryAction';
import { MoreVert } from '@material-ui/icons';
import { compose, pathOr, take } from 'ramda';
import { HexagonOutline } from 'mdi-material-ui';
import inject18n from '../../../components/i18n';
import ItemMarking from '../../../components/ItemMarking';
import ReportRefPopover from './ReportRefPopover';

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
    right: 10,
    marginRight: 0,
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

class ReportObservableLineComponent extends Component {
  render() {
    const {
      t,
      fd,
      classes,
      node,
      dataColumns,
      reportId,
      paginationOptions,
    } = this.props;
    return (
      <ListItem
        classes={{ root: classes.item }}
        divider={true}
        button={true}
        component={Link}
        to={`/dashboard/signatures/observables/${node.id}`}
      >
        <ListItemIcon classes={{ root: classes.itemIcon }}>
          <HexagonOutline />
        </ListItemIcon>
        <ListItemText
          primary={
            <div>
              <div
                className={classes.bodyItem}
                style={{ width: dataColumns.entity_type.width }}
              >
                {t(`observable_${node.entity_type}`)}
              </div>
              <div
                className={classes.bodyItem}
                style={{ width: dataColumns.observable_value.width }}
              >
                {node.observable_value}
              </div>
              <div
                className={classes.bodyItem}
                style={{ width: dataColumns.createdByRef.width }}
              >
                {pathOr('', ['createdByRef', 'node', 'name'], node)}
              </div>
              <div
                className={classes.bodyItem}
                style={{ width: dataColumns.created_at.width }}
              >
                {fd(node.created_at)}
              </div>
              <div
                className={classes.bodyItem}
                style={{ width: dataColumns.markingDefinitions.width }}
              >
                {take(1, pathOr([], ['markingDefinitions', 'edges'], node)).map(
                  (markingDefinition) => (
                    <ItemMarking
                      key={markingDefinition.node.id}
                      variant="inList"
                      label={markingDefinition.node.definition}
                      color={markingDefinition.node.color}
                    />
                  ),
                )}
              </div>
            </div>
          }
        />
        <ListItemSecondaryAction classes={{ root: classes.goIcon }}>
          <ReportRefPopover
            reportId={reportId}
            toId={node.id}
            relationType="observable_refs"
            paginationKey="Pagination_observableRefs"
            paginationOptions={paginationOptions}
          />
        </ListItemSecondaryAction>
      </ListItem>
    );
  }
}

ReportObservableLineComponent.propTypes = {
  reportId: PropTypes.string,
  dataColumns: PropTypes.object,
  node: PropTypes.object,
  classes: PropTypes.object,
  fd: PropTypes.func,
  t: PropTypes.func,
  paginationOptions: PropTypes.object,
};

const ReportObservableLineFragment = createFragmentContainer(
  ReportObservableLineComponent,
  {
    node: graphql`
      fragment ReportObservableLine_node on StixObservable {
        id
        observable_value
        entity_type
        created_at
        createdByRef {
          node {
            name
          }
        }
        markingDefinitions {
          edges {
            node {
              id
              definition
              color
            }
          }
        }
      }
    `,
  },
);

export const ReportObservableLine = compose(
  inject18n,
  withStyles(styles),
)(ReportObservableLineFragment);

class ReportObservableLineDummyComponent extends Component {
  render() {
    const { classes, dataColumns } = this.props;
    return (
      <ListItem classes={{ root: classes.item }} divider={true}>
        <ListItemIcon classes={{ root: classes.itemIconDisabled }}>
          <HexagonOutline />
        </ListItemIcon>
        <ListItemText
          primary={
            <div>
              <div
                className={classes.bodyItem}
                style={{ width: dataColumns.entity_type.width }}
              >
                <div className="fakeItem" style={{ width: '80%' }} />
              </div>
              <div
                className={classes.bodyItem}
                style={{ width: dataColumns.observable_value.width }}
              >
                <div className="fakeItem" style={{ width: '80%' }} />
              </div>
              <div
                className={classes.bodyItem}
                style={{ width: dataColumns.createdByRef.width }}
              >
                <div className="fakeItem" style={{ width: '70%' }} />
              </div>
              <div
                className={classes.bodyItem}
                style={{ width: dataColumns.created_at.width }}
              >
                <div className="fakeItem" style={{ width: '80%' }} />
              </div>
              <div
                className={classes.bodyItem}
                style={{ width: dataColumns.markingDefinitions.width }}
              >
                <div className="fakeItem" style={{ width: 100 }} />
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

ReportObservableLineDummyComponent.propTypes = {
  classes: PropTypes.object,
  dataColumns: PropTypes.object,
};

export const ReportObservableLineDummy = compose(
  inject18n,
  withStyles(styles),
)(ReportObservableLineDummyComponent);
