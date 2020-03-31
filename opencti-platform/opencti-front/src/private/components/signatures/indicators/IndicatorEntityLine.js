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
import ItemConfidenceLevel from '../../../../components/ItemConfidenceLevel';
import StixRelationPopover from '../../common/stix_relations/StixRelationPopover';
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
  itemIconDisabled: {
    color: theme.palette.grey[700],
  },
  placeholder: {
    display: 'inline-block',
    height: '1em',
    backgroundColor: theme.palette.grey[700],
  },
});

class IndicatorEntityLineComponent extends Component {
  render() {
    const {
      nsd,
      t,
      classes,
      dataColumns,
      node,
      paginationOptions,
      displayRelation,
      entityId,
    } = this.props;
    const link = node.to.parent_types.includes('stix_relation')
      ? `/dashboard/signatures/indicators/${entityId}/knowledge/relations/${node.id}`
      : `${resolveLink(node.to.entity_type)}/${
        node.to.id
      }/indicators/relations/${node.id}`;
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
                {t(
                  `entity_${
                    node.to.entity_type === 'stix_relation'
                    || node.to.entity_type === 'stix-relation'
                      ? node.to.parent_types[0]
                      : node.to.entity_type
                  }`,
                )}
              </div>
              <div
                className={classes.bodyItem}
                style={{ width: dataColumns.name.width }}
              >
                {node.to.entity_type === 'stix_relation'
                || node.to.entity_type === 'stix-relation'
                  ? `${node.to.from.name} ${String.fromCharCode(8594)} ${
                    node.to.to.name
                  }`
                  : node.to.name}
              </div>
              {!displayRelation ? (
                <div
                  className={classes.bodyItem}
                  style={{ width: dataColumns.role_played.width }}
                >
                  {/* eslint-disable-next-line no-nested-ternary */}
                  {node.inferred
                    ? '-'
                    : node.role_played
                      ? t(node.role_played)
                      : t('Unknown')}
                </div>
              ) : (
                ''
              )}
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

IndicatorEntityLineComponent.propTypes = {
  paginationOptions: PropTypes.object,
  dataColumns: PropTypes.object,
  node: PropTypes.object,
  classes: PropTypes.object,
  t: PropTypes.func,
  nsd: PropTypes.func,
  displayRelation: PropTypes.bool,
  entityId: PropTypes.string,
};

const IndicatorEntityLineFragment = createFragmentContainer(
  IndicatorEntityLineComponent,
  {
    node: graphql`
      fragment IndicatorEntityLine_node on StixRelation {
        id
        relationship_type
        weight
        first_seen
        last_seen
        description
        role_played
        inferred
        to {
          id
          name
          description
          parent_types
          entity_type
          created_at
          updated_at
          ... on StixRelation {
            from {
              name
            }
            to {
              name
            }
          }
        }
      }
    `,
  },
);

export const IndicatorEntityLine = compose(
  inject18n,
  withStyles(styles),
)(IndicatorEntityLineFragment);

class IndicatorEntityLineDummyComponent extends Component {
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
                style={{ width: dataColumns.name.width }}
              >
                <div className="fakeItem" style={{ width: '80%' }} />
              </div>
              {!displayRelation ? (
                <div
                  className={classes.bodyItem}
                  style={{ width: dataColumns.role_played.width }}
                >
                  <div className="fakeItem" style={{ width: '80%' }} />
                </div>
              ) : (
                ''
              )}
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
          <MoreVert />
        </ListItemSecondaryAction>
      </ListItem>
    );
  }
}

IndicatorEntityLineDummyComponent.propTypes = {
  dataColumns: PropTypes.object,
  classes: PropTypes.object,
  displayRelation: PropTypes.bool,
};

export const IndicatorEntityLineDummy = compose(
  inject18n,
  withStyles(styles),
)(IndicatorEntityLineDummyComponent);
