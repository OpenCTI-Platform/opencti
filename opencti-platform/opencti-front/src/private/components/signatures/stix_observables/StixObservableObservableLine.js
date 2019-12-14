import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import { compose } from 'ramda';
import { Link } from 'react-router-dom';
import { createFragmentContainer } from 'react-relay';
import graphql from 'babel-plugin-relay/macro';
import { withStyles } from '@material-ui/core/styles';
import ListItem from '@material-ui/core/ListItem';
import ListItemIcon from '@material-ui/core/ListItemIcon';
import ListItemText from '@material-ui/core/ListItemText';
import ListItemSecondaryAction from '@material-ui/core/ListItemSecondaryAction';
import { Help, MoreVert } from '@material-ui/icons';
import inject18n from '../../../../components/i18n';
import StixObservableRelationPopover from '../../common/stix_observable_relations/StixObservableRelationPopover';
import { resolveLink } from '../../../../utils/Entity';
import ItemIcon from '../../../../components/ItemIcon';

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

class StixObservableObservableLineComponent extends Component {
  render() {
    const {
      nsd,
      t,
      classes,
      dataColumns,
      node,
      paginationOptions,
      displayRelation,
    } = this.props;
    const link = `${resolveLink(node.to.entity_type)}/${node.to.id}`;
    return (
      <ListItem
        classes={{ root: classes.item }}
        divider={true}
        button={true}
        component={Link}
        to={link}
      >
        <ListItemIcon classes={{ root: classes.itemIcon }}>
          <ItemIcon type={node.to.entity_type} />
        </ListItemIcon>
        <ListItemText
          primary={
            <div>
              {displayRelation ? (
                <div
                  className={classes.bodyItem}
                  style={{ width: dataColumns.relationship_type.width }}
                >
                  {t(`relation_${node.relationship_type}`)}
                </div>
              ) : (
                ''
              )}
              <div
                className={classes.bodyItem}
                style={{ width: dataColumns.entity_type.width }}
              >
                {t(`observable_${node.to.entity_type}`)}
              </div>
              <div
                className={classes.bodyItem}
                style={{ width: dataColumns.observable_value.width }}
              >
                {node.to.observable_value}
              </div>
              <div
                className={classes.bodyItem}
                style={{ width: dataColumns.role_played.width }}
              >
                {node.role_played ? t(node.role_played) : t('Unknown')}
              </div>
              <div
                className={classes.bodyItem}
                style={{ width: dataColumns.first_seen.width }}
              >
                {node.inferred ? '-' : nsd(node.first_seen)}
              </div>
              <div
                className={classes.bodyItem}
                style={{ width: dataColumns.last_seen.width }}
              >
                {node.inferred ? '-' : nsd(node.last_seen)}
              </div>
            </div>
          }
        />
        <ListItemSecondaryAction>
          <StixObservableRelationPopover
            stixObservableRelationId={node.id}
            paginationOptions={paginationOptions}
            disabled={node.inferred}
          />
        </ListItemSecondaryAction>
      </ListItem>
    );
  }
}

StixObservableObservableLineComponent.propTypes = {
  paginationOptions: PropTypes.object,
  dataColumns: PropTypes.object,
  node: PropTypes.object,
  classes: PropTypes.object,
  t: PropTypes.func,
  nsd: PropTypes.func,
  displayRelation: PropTypes.bool,
};

const StixObservableObservableLineFragment = createFragmentContainer(
  StixObservableObservableLineComponent,
  {
    node: graphql`
      fragment StixObservableObservableLine_node on StixObservableRelation {
        id
        relationship_type
        role_played
        first_seen
        last_seen
        to {
          id
          entity_type
          observable_value
          created_at
          updated_at
        }
      }
    `,
  },
);

export const StixObservableObservableLine = compose(
  inject18n,
  withStyles(styles),
)(StixObservableObservableLineFragment);

class StixObservableObservableLineDummyComponent extends Component {
  render() {
    const { classes, dataColumns, displayRelation } = this.props;
    return (
      <ListItem classes={{ root: classes.item }} divider={true}>
        <ListItemIcon classes={{ root: classes.itemIconDisabled }}>
          <Help />
        </ListItemIcon>
        <ListItemText
          primary={
            <div>
              {displayRelation ? (
                <div
                  className={classes.bodyItem}
                  style={{ width: dataColumns.relationship_type.width }}
                >
                  <div className="fakeItem" style={{ width: '80%' }} />
                </div>
              ) : (
                ''
              )}
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
                style={{ width: dataColumns.role_played.width }}
              >
                <div className="fakeItem" style={{ width: '80%' }} />
              </div>
              <div
                className={classes.bodyItem}
                style={{ width: dataColumns.first_seen.width }}
              >
                <div className="fakeItem" style={{ width: '80%' }} />
              </div>
              <div
                className={classes.bodyItem}
                style={{ width: dataColumns.last_seen.width }}
              >
                <div className="fakeItem" style={{ width: '80%' }} />
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

StixObservableObservableLineDummyComponent.propTypes = {
  dataColumns: PropTypes.object,
  classes: PropTypes.object,
  displayRelation: PropTypes.bool,
};

export const StixObservableObservableLineDummy = compose(
  inject18n,
  withStyles(styles),
)(StixObservableObservableLineDummyComponent);
