import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import { Link } from 'react-router-dom';
import { createFragmentContainer, graphql } from 'react-relay';
import withStyles from '@mui/styles/withStyles';
import ListItem from '@mui/material/ListItem';
import ListItemIcon from '@mui/material/ListItemIcon';
import ListItemText from '@mui/material/ListItemText';
import { KeyboardArrowRightOutlined } from '@mui/icons-material';
import { compose } from 'ramda';
import Checkbox from '@mui/material/Checkbox';
import Skeleton from '@mui/material/Skeleton';
import Tooltip from '@mui/material/Tooltip';
import Chip from '@mui/material/Chip';
import inject18n from '../../../../components/i18n';
import StixCoreObjectLabels from '../../common/stix_core_objects/StixCoreObjectLabels';
import ItemMarkings from '../../../../components/ItemMarkings';
import ItemIcon from '../../../../components/ItemIcon';
import ItemStatus from '../../../../components/ItemStatus';

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
    paddingRight: 10,
  },
  goIcon: {
    position: 'absolute',
    right: -10,
  },
  itemIconDisabled: {
    color: theme.palette.grey[700],
  },
  placeholder: {
    display: 'inline-block',
    height: '1em',
    backgroundColor: theme.palette.grey[700],
  },
  chipInList: {
    fontSize: 12,
    height: 20,
    float: 'left',
    width: 120,
    borderRadius: 4,
    backgroundColor: theme.palette.background.default,
    color: theme.palette.chip.main,
    border: `1px solid ${theme.palette.primary.main}`,
  },
});

class GroupingLineComponent extends Component {
  render() {
    const {
      fd,
      classes,
      node,
      dataColumns,
      onLabelClick,
      onToggleEntity,
      selectedElements,
      deSelectedElements,
      selectAll,
      onToggleShiftEntity,
      index,
    } = this.props;
    return (
      <ListItem
        classes={{ root: classes.item }}
        divider={true}
        button={true}
        component={Link}
        to={`/dashboard/analyses/groupings/${node.id}`}
      >
        <ListItemIcon
          classes={{ root: classes.itemIcon }}
          style={{ minWidth: 40 }}
          onClick={(event) => (event.shiftKey
            ? onToggleShiftEntity(index, node, event)
            : onToggleEntity(node, event))
          }
        >
          <Checkbox
            edge="start"
            checked={
              (selectAll && !(node.id in (deSelectedElements || {})))
              || node.id in (selectedElements || {})
            }
            disableRipple={true}
          />
        </ListItemIcon>
        <ListItemIcon classes={{ root: classes.itemIcon }}>
          <ItemIcon type="Grouping" />
        </ListItemIcon>
        <ListItemText
          primary={
            <>
              <Tooltip title={node.name}>
                <div
                  className={classes.bodyItem}
                  style={{ width: dataColumns.name.width }}
                >
                  {node.name}
                </div>
              </Tooltip>
              <Tooltip title={node.name}>
                <div
                  className={classes.bodyItem}
                  style={{ width: dataColumns.context.width }}
                >
                  <Chip
                    classes={{ root: classes.chipInList }}
                    color="primary"
                    variant="outlined"
                    label={node.context}
                  />
                </div>
              </Tooltip>
              <div
                className={classes.bodyItem}
                style={{ width: dataColumns.createdBy.width }}
              >
                {node.createdBy?.name}
              </div>
              <div
                className={classes.bodyItem}
                style={{ width: dataColumns.creator.width }}
              >
                {(node.creators ?? []).map((c) => c?.name).join(', ')}
              </div>
              <div
                className={classes.bodyItem}
                style={{ width: dataColumns.objectLabel.width }}
              >
                <StixCoreObjectLabels
                  variant="inList"
                  labels={node.objectLabel}
                  onClick={onLabelClick.bind(this)}
                />
              </div>
              <div
                className={classes.bodyItem}
                style={{ width: dataColumns.created.width }}
              >
                {fd(node.created)}
              </div>
              <div
                className={classes.bodyItem}
                style={{ width: dataColumns.x_opencti_workflow_id.width }}
              >
                <ItemStatus
                  status={node.status}
                  variant="inList"
                  disabled={!node.workflowEnabled}
                />
              </div>
              <div
                className={classes.bodyItem}
                style={{ width: dataColumns.objectMarking.width }}
              >
                <ItemMarkings
                  variant="inList"
                  markingDefinitions={node.objectMarking ?? []}
                  limit={1}
                />
              </div>
            </>
          }
        />
        <ListItemIcon classes={{ root: classes.goIcon }}>
          <KeyboardArrowRightOutlined />
        </ListItemIcon>
      </ListItem>
    );
  }
}

GroupingLineComponent.propTypes = {
  dataColumns: PropTypes.object,
  node: PropTypes.object,
  classes: PropTypes.object,
  fd: PropTypes.func,
  t: PropTypes.func,
  onLabelClick: PropTypes.func,
  onToggleEntity: PropTypes.func,
  selectedElements: PropTypes.object,
  deSelectedElements: PropTypes.object,
  selectAll: PropTypes.bool,
};

const GroupingLineFragment = createFragmentContainer(GroupingLineComponent, {
  node: graphql`
    fragment GroupingLine_node on Grouping {
      id
      entity_type
      created
      name
      description
      context
      createdBy {
        ... on Identity {
          id
          name
          entity_type
        }
      }
      objectMarking {
        id
        definition_type
        definition
        x_opencti_order
        x_opencti_color
      }
      objectLabel {
        id
        value
        color
      }
      creators {
        id
        name
      }
      status {
        id
        order
        template {
          name
          color
        }
      }
      workflowEnabled
    }
  `,
});

export const GroupingLine = compose(
  inject18n,
  withStyles(styles),
)(GroupingLineFragment);

class GroupingLineDummyComponent extends Component {
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
        <ListItemIcon classes={{ root: classes.itemIcon }}>
          <Skeleton
            animation="wave"
            variant="circular"
            width={30}
            height={30}
          />
        </ListItemIcon>
        <ListItemText
          primary={
            <div>
              <div
                className={classes.bodyItem}
                style={{ width: dataColumns.name.width }}
              >
                <Skeleton
                  animation="wave"
                  variant="rectangular"
                  width="90%"
                  height="100%"
                />
              </div>
              <div
                className={classes.bodyItem}
                style={{ width: dataColumns.context.width }}
              >
                <Skeleton
                  animation="wave"
                  variant="rectangular"
                  width="90%"
                  height="100%"
                />
              </div>
              <div
                className={classes.bodyItem}
                style={{ width: dataColumns.createdBy.width }}
              >
                <Skeleton
                  animation="wave"
                  variant="rectangular"
                  width="90%"
                  height="100%"
                />
              </div>
              <div
                className={classes.bodyItem}
                style={{ width: dataColumns.creator.width }}
              >
                <Skeleton
                  animation="wave"
                  variant="rectangular"
                  width="90%"
                  height="100%"
                />
              </div>
              <div
                className={classes.bodyItem}
                style={{ width: dataColumns.objectLabel.width }}
              >
                <Skeleton
                  animation="wave"
                  variant="rectangular"
                  width="90%"
                  height="100%"
                />
              </div>
              <div
                className={classes.bodyItem}
                style={{ width: dataColumns.created.width }}
              >
                <Skeleton
                  animation="wave"
                  variant="rectangular"
                  width="90%"
                  height="100%"
                />
              </div>
              <div
                className={classes.bodyItem}
                style={{ width: dataColumns.x_opencti_workflow_id.width }}
              >
                <Skeleton
                  animation="wave"
                  variant="rectangular"
                  width="90%"
                  height="100%"
                />
              </div>
              <div
                className={classes.bodyItem}
                style={{ width: dataColumns.objectMarking.width }}
              >
                <Skeleton
                  animation="wave"
                  variant="rectangular"
                  width={100}
                  height="100%"
                />
              </div>
            </div>
          }
        />
        <ListItemIcon classes={{ root: classes.goIcon }}>
          <KeyboardArrowRightOutlined />
        </ListItemIcon>
      </ListItem>
    );
  }
}

GroupingLineDummyComponent.propTypes = {
  classes: PropTypes.object,
  dataColumns: PropTypes.object,
};

export const GroupingLineDummy = compose(
  inject18n,
  withStyles(styles),
)(GroupingLineDummyComponent);
