import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import { compose } from 'ramda';
import { Link } from 'react-router-dom';
import { createFragmentContainer } from 'react-relay';
import graphql from 'babel-plugin-relay/macro';
import { withStyles } from '@material-ui/core/styles';
import ListItem from '@material-ui/core/ListItem';
import ListItemIcon from '@material-ui/core/ListItemIcon';
import ListItemSecondaryAction from '@material-ui/core/ListItemSecondaryAction';
import Checkbox from '@material-ui/core/Checkbox';
import ListItemText from '@material-ui/core/ListItemText';
import Skeleton from '@material-ui/lab/Skeleton';
import inject18n from '../../../../../components/i18n';
import CyioCoreObjectLabels from '../../../common/stix_core_objects/CyioCoreObjectLabels';
import EntitiesAssessmentPlatformsPopover from './EntitiesAssessmentPlatformsPopover';

const styles = (theme) => ({
  item: {
    paddingLeft: 10,
    height: 50,
    borderTop: `0.75px solid ${theme.palette.dataView.border}`,
    borderBottom: `0.75px solid ${theme.palette.dataView.border}`,
  },
  selectedItem: {
    paddingLeft: 10,
    height: 50,
    borderTop: `0.75px solid ${theme.palette.dataView.selectedBorder}`,
    borderBottom: `0.75px solid ${theme.palette.dataView.selectedBorder}`,
    background: theme.palette.dataView.selectedBackgroundColor,
  },
  itemIcon: {
    color: theme.palette.primary.main,
  },
  bodyItem: {
    height: 20,
    fontSize: 13,
    paddingLeft: 24,
    float: 'left',
    whiteSpace: 'nowrap',
    overflow: 'hidden',
    textOverflow: 'ellipsis',
  },
  goIcon: {
    minWidth: '0px',
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

class EntityAssessmentPlatformLineComponent extends Component {
  render() {
    const {
      t,
      fd,
      history,
      classes,
      node,
      selectAll,
      dataColumns,
      onLabelClick,
      onToggleEntity,
      selectedElements,
    } = this.props;
    return (
      <ListItem
        classes={{
          root: (selectAll || node.id in (selectedElements || {}))
            ? classes.selectedItem : classes.item,
        }}
        divider={true}
        button={true}
        component={Link}
        selected={selectAll || node.id in (selectedElements || {})}
        to={`/data/entities/assessment_platform/${node.id}`}
      >
        <ListItemIcon
          classes={{ root: classes.itemIcon }}
          style={{ minWidth: 38 }}
          onClick={onToggleEntity.bind(this, node)}
        >
          <Checkbox
            edge="start"
            color='primary'
            checked={selectAll || node.id in (selectedElements || {})}
            disableRipple={true}
          />
        </ListItemIcon>
        <ListItemText
          primary={
            <div>
              <div
                className={classes.bodyItem}
                style={{ height: '24px', width: dataColumns.type.width }}
              >
                {node.entity_type && t(node.entity_type)}
              </div>
              <div
                className={classes.bodyItem}
                style={{ width: '14.5%' }}
              >
                {node.name && t(node.name)}
              </div>
              <div
                className={classes.bodyItem}
                style={{ width: dataColumns.author.width }}
              >
                {/* {node.entity_type && t(node.entity_type)} */}
              </div>
              <div
                className={classes.bodyItem}
                style={{ width: '21.7%' }}
              >
                <CyioCoreObjectLabels
                  variant="inList"
                  labels={node.labels}
                  onClick={onLabelClick.bind(this)}
                />
              </div>
              <div
                className={classes.bodyItem}
                style={{ width: dataColumns.created.width }}
              >
                {node.created && fd(node.created)}
              </div>
              <div
                className={classes.bodyItem}
                style={{ width: dataColumns.marking.width }}
              >
                {node?.parent_types && t(node.parent_types)}
              </div>
            </div>
          }
        />
        <ListItemSecondaryAction classes={{ root: classes.goIcon }}>
          <EntitiesAssessmentPlatformsPopover
            history={history}
            nodeId={node?.id}
            // riskNode={riskData.node}
            node={node}
          />
        </ListItemSecondaryAction>
      </ListItem>
    );
  }
}

EntityAssessmentPlatformLineComponent.propTypes = {
  dataColumns: PropTypes.object,
  node: PropTypes.object,
  classes: PropTypes.object,
  history: PropTypes.object,
  fd: PropTypes.func,
  t: PropTypes.func,
  onLabelClick: PropTypes.func,
};

const EntityAssessmentPlatformLineFragment = createFragmentContainer(
  EntityAssessmentPlatformLineComponent,
  {
    node: graphql`
      fragment EntityAssessmentPlatformLine_node on AssessmentPlatform {
        __typename
        id
        entity_type
        description
        name
        created
        modified
        labels {
          __typename
          id
          name
          color
          entity_type
          description
        }
        links {
          __typename
          id
          source_name
          description
          entity_type
          url
          hashes {
            value
          }
          external_id
        }
        remarks {
          __typename
          id
          entity_type
          abstract
          content
          authors
        }
      }
    `,
  },
);

export const EntityAssessmentPlatformLine = compose(
  inject18n,
  withStyles(styles),
)(EntityAssessmentPlatformLineFragment);

class EntityAssessmentPlatformLineDummyComponent extends Component {
  render() {
    const { classes, dataColumns } = this.props;
    return (
      <ListItem classes={{ root: classes.item }} divider={true}>
        <ListItemIcon classes={{ root: classes.itemIconDisabled }}>
          <Skeleton animation="wave" variant="circle" width={30} height={30} />
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
                  variant="rect"
                  width="90%"
                  height="100%"
                />
              </div>
              <div
                className={classes.bodyItem}
                style={{ width: dataColumns.type.width }}
              >
                <Skeleton
                  animation="wave"
                  variant="rect"
                  width="90%"
                  height="100%"
                />
              </div>
              <div
                className={classes.bodyItem}
                style={{ width: dataColumns.author.width }}
              >
                <Skeleton
                  animation="wave"
                  variant="rect"
                  width={140}
                  height="100%"
                />
              </div>
              <div
                className={classes.bodyItem}
                style={{ width: dataColumns.label_name.width }}
              >
                <Skeleton
                  animation="wave"
                  variant="rect"
                  width={140}
                  height="100%"
                />
              </div>
              <div
                className={classes.bodyItem}
                style={{ width: dataColumns.created.width }}
              >
                <Skeleton
                  animation="wave"
                  variant="rect"
                  width={140}
                  height="100%"
                />
              </div>
              <div
                className={classes.bodyItem}
                style={{ width: dataColumns.marking.width }}
              >
                <Skeleton
                  animation="wave"
                  variant="rect"
                  width="90%"
                  height="100%"
                />
              </div>
            </div>
          }
        />
      </ListItem>
    );
  }
}

EntityAssessmentPlatformLineDummyComponent.propTypes = {
  classes: PropTypes.object,
  dataColumns: PropTypes.object,
};

export const EntityAssessmentPlatformLineDummy = compose(
  inject18n,
  withStyles(styles),
)(EntityAssessmentPlatformLineDummyComponent);
