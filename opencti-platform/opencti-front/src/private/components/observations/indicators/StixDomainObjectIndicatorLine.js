import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import { compose, pathOr, take } from 'ramda';
import { Link } from 'react-router-dom';
import { createFragmentContainer } from 'react-relay';
import graphql from 'babel-plugin-relay/macro';
import { withStyles } from '@material-ui/core/styles';
import ListItem from '@material-ui/core/ListItem';
import ListItemIcon from '@material-ui/core/ListItemIcon';
import ListItemText from '@material-ui/core/ListItemText';
import ListItemSecondaryAction from '@material-ui/core/ListItemSecondaryAction';
import { MoreVert } from '@material-ui/icons';
import { ShieldSearch } from 'mdi-material-ui';
import Checkbox from '@material-ui/core/Checkbox';
import inject18n from '../../../../components/i18n';
import ItemPatternType from '../../../../components/ItemPatternType';
import StixCoreObjectLabels from '../../common/stix_core_objects/StixCoreObjectLabels';
import ItemMarking from '../../../../components/ItemMarking';
import StixCoreRelationshipFromAndToPopover from '../../common/stix_core_relationships/StixCoreRelationshipFromAndToPopover';

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

class StixDomainObjectIndicatorLineComponent extends Component {
  render() {
    const {
      nsd,
      classes,
      dataColumns,
      node,
      paginationOptions,
      entityId,
      onToggleEntity,
      selectedElements,
      selectAll,
    } = this.props;
    return (
      <ListItem
        classes={{ root: classes.item }}
        divider={true}
        button={true}
        component={Link}
        to={`/dashboard/observations/indicators/${node.id}`}
      >
        <ListItemIcon
          classes={{ root: classes.itemIcon }}
          style={{ minWidth: 40 }}
          onClick={onToggleEntity.bind(this, node)}
        >
          <Checkbox
            edge="start"
            checked={selectAll || node.id in (selectedElements || {})}
            disableRipple={true}
          />
        </ListItemIcon>
        <ListItemIcon classes={{ root: classes.itemIcon }}>
          <ShieldSearch />
        </ListItemIcon>
        <ListItemText
          primary={
            <div>
              <div
                className={classes.bodyItem}
                style={{ width: dataColumns.pattern_type.width }}
              >
                <ItemPatternType variant="inList" label={node.pattern_type} />
              </div>
              <div
                className={classes.bodyItem}
                style={{ width: dataColumns.name.width }}
              >
                {node.name}
              </div>
              <div
                className={classes.bodyItem}
                style={{ width: dataColumns.objectLabel.width }}
              >
                <StixCoreObjectLabels
                  variant="inList"
                  labels={node.objectLabel}
                />
              </div>
              <div
                className={classes.bodyItem}
                style={{ width: dataColumns.created_at.width }}
              >
                {nsd(node.created_at)}
              </div>
              <div
                className={classes.bodyItem}
                style={{ width: dataColumns.valid_until.width }}
              >
                {nsd(node.valid_until)}
              </div>
              <div
                className={classes.bodyItem}
                style={{ width: dataColumns.objectMarking.width }}
              >
                {take(1, pathOr([], ['objectMarking', 'edges'], node)).map(
                  (markingDefinition) => (
                    <ItemMarking
                      key={markingDefinition.node.id}
                      variant="inList"
                      label={markingDefinition.node.definition}
                      color={markingDefinition.node.x_opencti_color}
                    />
                  ),
                )}
              </div>
            </div>
          }
        />
        <ListItemSecondaryAction>
          <StixCoreRelationshipFromAndToPopover
            fromId={node.id}
            toId={entityId}
            nodeId={node.id}
            relationshipType="indicates"
            paginationOptions={paginationOptions}
            connectionKey="Pagination_indicators"
          />
        </ListItemSecondaryAction>
      </ListItem>
    );
  }
}

StixDomainObjectIndicatorLineComponent.propTypes = {
  dataColumns: PropTypes.object,
  entityId: PropTypes.string,
  paginationOptions: PropTypes.object,
  node: PropTypes.object,
  classes: PropTypes.object,
  t: PropTypes.func,
  nsd: PropTypes.func,
};

const StixDomainObjectIndicatorLineFragment = createFragmentContainer(
  StixDomainObjectIndicatorLineComponent,
  {
    node: graphql`
      fragment StixDomainObjectIndicatorLine_node on Indicator {
        id
        entity_type
        name
        pattern_type
        description
        valid_from
        valid_until
        created
        created_at
        x_opencti_score
        x_opencti_main_observable_type
        objectMarking {
          edges {
            node {
              id
              definition
              x_opencti_color
            }
          }
        }
        objectLabel {
          edges {
            node {
              id
              value
              color
            }
          }
        }
      }
    `,
  },
);

export const StixDomainObjectIndicatorLine = compose(
  inject18n,
  withStyles(styles),
)(StixDomainObjectIndicatorLineFragment);

class StixDomainObjectIndicatorLineDummyComponent extends Component {
  render() {
    const { classes, dataColumns } = this.props;
    return (
      <ListItem classes={{ root: classes.item }} divider={true}>
        <ListItemIcon
          classes={{ root: classes.itemIconDisabled }}
          style={{ minWidth: 40 }}
        >
          <Checkbox edge="start" disabled={true} disableRipple={true} />
        </ListItemIcon>
        <ListItemIcon classes={{ root: classes.itemIconDisabled }}>
          <ShieldSearch />
        </ListItemIcon>
        <ListItemText
          primary={
            <div>
              <div
                className={classes.bodyItem}
                style={{ width: dataColumns.pattern_type.width }}
              >
                <div className="fakeItem" style={{ width: '80%' }} />
              </div>
              <div
                className={classes.bodyItem}
                style={{ width: dataColumns.name.width }}
              >
                <div className="fakeItem" style={{ width: '80%' }} />
              </div>
              <div
                className={classes.bodyItem}
                style={{ width: dataColumns.objectLabel.width }}
              >
                <div className="fakeItem" style={{ width: '80%' }} />
              </div>
              <div
                className={classes.bodyItem}
                style={{ width: dataColumns.created_at.width }}
              >
                <div className="fakeItem" style={{ width: '80%' }} />
              </div>
              <div
                className={classes.bodyItem}
                style={{ width: dataColumns.valid_until.width }}
              >
                <div className="fakeItem" style={{ width: '80%' }} />
              </div>
              <div
                className={classes.bodyItem}
                style={{ width: dataColumns.objectMarking.width }}
              >
                <div className="fakeItem" style={{ width: 80 }} />
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

StixDomainObjectIndicatorLineDummyComponent.propTypes = {
  classes: PropTypes.object,
  dataColumns: PropTypes.object,
};

export const StixDomainObjectIndicatorLineDummy = compose(
  inject18n,
  withStyles(styles),
)(StixDomainObjectIndicatorLineDummyComponent);
