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
import { MoreVertOutlined, HelpOutlined } from '@material-ui/icons';
import inject18n from '../../../../components/i18n';
import ItemIcon from '../../../../components/ItemIcon';
import ItemConfidenceLevel from '../../../../components/ItemConfidenceLevel';
import StixRelationPopover from './StixRelationPopover';

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
  itemIconDisabled: {
    color: theme.palette.grey[700],
  },
  placeholder: {
    display: 'inline-block',
    height: '1em',
    backgroundColor: theme.palette.grey[700],
  },
});

class EntityStixRelationLineComponent extends Component {
  render() {
    const {
      nsd,
      t,
      classes,
      dataColumns,
      node,
      paginationOptions,
      entityLink,
    } = this.props;
    const link = `${entityLink}/relations/${node.id}`;
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
              <div
                className={classes.bodyItem}
                style={{ width: dataColumns.name.width }}
              >
                {node.to.name}
              </div>
              <div
                className={classes.bodyItem}
                style={{ width: dataColumns.entity_type.width }}
              >
                {t(`entity_${node.to.entity_type}`)}
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
              <div
                className={classes.bodyItem}
                style={{ width: dataColumns.weight.width }}
              >
                <ItemConfidenceLevel
                  level={node.inferred ? 99 : node.weight}
                  variant="inList"
                />
              </div>
            </div>
          }
        />
        <ListItemSecondaryAction>
          <StixRelationPopover
            stixRelationId={node.id}
            paginationOptions={paginationOptions}
            disabled={node.inferred}
          />
        </ListItemSecondaryAction>
      </ListItem>
    );
  }
}

EntityStixRelationLineComponent.propTypes = {
  dataColumns: PropTypes.object,
  entityLink: PropTypes.string,
  paginationOptions: PropTypes.object,
  node: PropTypes.object,
  classes: PropTypes.object,
  t: PropTypes.func,
  nsd: PropTypes.func,
};

const EntityStixRelationLineFragment = createFragmentContainer(
  EntityStixRelationLineComponent,
  {
    node: graphql`
      fragment EntityStixRelationLine_node on StixRelation {
        id
        entity_type
        parent_types
        relationship_type
        weight
        first_seen
        last_seen
        description
        inferred
        role_played
        to {
          ... on StixDomainEntity {
            id
            entity_type
            parent_types
            name
            description
            created_at
            updated_at
          }
          ... on AttackPattern {
            external_id
            killChainPhases {
              edges {
                node {
                  id
                  phase_name
                  phase_order
                }
              }
            }
          }
          ... on StixObservable {
            id
            entity_type
            parent_types
            observable_value
          }
          ... on Indicator {
            id
            name
            main_observable_type
            description
            valid_from
            valid_until
            score
            created
          }
        }
        killChainPhases {
          edges {
            node {
              id
              phase_name
              phase_order
            }
          }
        }
      }
    `,
  },
);

export const EntityStixRelationLine = compose(
  inject18n,
  withStyles(styles),
)(EntityStixRelationLineFragment);

class EntityStixRelationLineDummyComponent extends Component {
  render() {
    const { classes, dataColumns } = this.props;
    return (
      <ListItem classes={{ root: classes.item }} divider={true}>
        <ListItemIcon classes={{ root: classes.itemIconDisabled }}>
          <HelpOutlined />
        </ListItemIcon>
        <ListItemText
          primary={
            <div>
              <div
                className={classes.bodyItem}
                style={{ width: dataColumns.name.width }}
              >
                <div className="fakeItem" style={{ width: '80%' }} />
              </div>
              <div
                className={classes.bodyItem}
                style={{ width: dataColumns.entity_type.width }}
              >
                <div className="fakeItem" style={{ width: '70%' }} />
              </div>
              <div
                className={classes.bodyItem}
                style={{ width: dataColumns.first_seen.width }}
              >
                <div className="fakeItem" style={{ width: 140 }} />
              </div>
              <div
                className={classes.bodyItem}
                style={{ width: dataColumns.last_seen.width }}
              >
                <div className="fakeItem" style={{ width: 140 }} />
              </div>
              <div
                className={classes.bodyItem}
                style={{ width: dataColumns.weight.width }}
              >
                <div className="fakeItem" style={{ width: 100 }} />
              </div>
            </div>
          }
        />
        <ListItemSecondaryAction classes={{ root: classes.itemIconDisabled }}>
          <MoreVertOutlined />
        </ListItemSecondaryAction>
      </ListItem>
    );
  }
}

EntityStixRelationLineDummyComponent.propTypes = {
  dataColumns: PropTypes.object,
  classes: PropTypes.object,
};

export const EntityStixRelationLineDummy = compose(
  inject18n,
  withStyles(styles),
)(EntityStixRelationLineDummyComponent);
