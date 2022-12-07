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
import EntitiesExternalReferencesPopover from './EntitiesExternalReferencesPopover';

const styles = (theme) => ({
  item: {
    paddingLeft: 10,
    height: 50,
    borderTop: '0.75px solid #1F2842',
    borderBottom: '0.75px solid #1F2842',
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

class EntityExternalReferenceLineComponent extends Component {
  render() {
    const {
      t,
      fd,
      classes,
      node,
      selectAll,
      dataColumns,
      onToggleEntity,
      selectedElements,
    } = this.props;
    return (
      <ListItem
        classes={{ root: classes.item }}
        style={{
          background: (selectAll || node.id in (selectedElements || {})) && 'linear-gradient(0deg, rgba(0, 0, 0, 0.5), rgba(0, 0, 0, 0.5)), #075AD3',
          borderTop: (selectAll || node.id in (selectedElements || {})) && '0.75px solid #075AD3',
          borderBottom: (selectAll || node.id in (selectedElements || {})) && '0.75px solid #075AD3',
        }}
        divider={true}
        button={true}
        component={Link}
        selected={selectAll || node.id in (selectedElements || {})}
        to={`/data/entities/external_references/${node.id}`}
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
                style={{ width: dataColumns.type.width }}
              >
                {node.entity_type && t(node.entity_type)}
              </div>
              <div
                className={classes.bodyItem}
                style={{ width: dataColumns.source_name.width }}
              >
                {node.source_name && t(node.source_name)}
              </div>
              <div
                className={classes.bodyItem}
                style={{ width: '16.5%' }}
              >
                {node.media_type && t(node.media_type)}
              </div>
              <div
                className={classes.bodyItem}
                style={{ width: '21%' }}
              >
                {node.url && t(node.url)}
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
                {/* {node?.parent_types && t(node.parent_types)} */}
              </div>
            </div>
          }
        />
        <ListItemSecondaryAction classes={{ root: classes.goIcon }}>
          <EntitiesExternalReferencesPopover
            // history={history}
            nodeId={node?.id}
            // riskNode={riskData.node}
            node={node}
          />
        </ListItemSecondaryAction>
      </ListItem>
    );
  }
}

EntityExternalReferenceLineComponent.propTypes = {
  dataColumns: PropTypes.object,
  node: PropTypes.object,
  classes: PropTypes.object,
  fd: PropTypes.func,
  t: PropTypes.func,
  onLabelClick: PropTypes.func,
};

const EntityExternalReferenceLineFragment = createFragmentContainer(
  EntityExternalReferenceLineComponent,
  {
    node: graphql`
      fragment EntityExternalReferenceLine_node on CyioExternalReference {
        __typename
        id
        url
        created
        media_type
        source_name
        entity_type
      }
    `,
  },
);

export const EntityExternalReferenceLine = compose(
  inject18n,
  withStyles(styles),
)(EntityExternalReferenceLineFragment);

class EntityExternalReferenceLineDummyComponent extends Component {
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
                style={{ width: '12.5%' }}
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
                style={{ width: '16.5%' }}
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
                style={{ width: '16.5%' }}
              >
                <Skeleton
                  animation="wave"
                  variant="rect"
                  width='90%'
                  height="100%"
                />
              </div>
              <div
                className={classes.bodyItem}
                style={{ width: '20%' }}
              >
                <Skeleton
                  animation="wave"
                  variant="rect"
                  width='90%'
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
                  width='90%'
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

EntityExternalReferenceLineDummyComponent.propTypes = {
  classes: PropTypes.object,
  dataColumns: PropTypes.object,
};

export const EntityExternalReferenceLineDummy = compose(
  inject18n,
  withStyles(styles),
)(EntityExternalReferenceLineDummyComponent);
