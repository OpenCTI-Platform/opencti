import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import { graphql, createFragmentContainer } from 'react-relay';
import withStyles from '@mui/styles/withStyles';
import ListItem from '@mui/material/ListItem';
import ListItemIcon from '@mui/material/ListItemIcon';
import ListItemText from '@mui/material/ListItemText';
import ListItemSecondaryAction from '@mui/material/ListItemSecondaryAction';
import { MoreVert, CenterFocusStrongOutlined } from '@mui/icons-material';
import { compose } from 'ramda';
import Skeleton from '@mui/material/Skeleton';
import inject18n from '../../../../components/i18n';
import MarkingDefinitionPopover from './MarkingDefinitionPopover';

const styles = (theme) => ({
  item: {
    paddingLeft: 10,
    height: 50,
    cursor: 'default',
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
    paddingRight: 5,
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
});

class MarkingDefinitionLineComponent extends Component {
  render() {
    const { fd, classes, node, dataColumns, paginationOptions } = this.props;
    return (
      <ListItem classes={{ root: classes.item }} divider={true} button={true}>
        <ListItemIcon
          style={{ color: node.x_opencti_color }}
          classes={{ root: classes.itemIcon }}
        >
          <CenterFocusStrongOutlined />
        </ListItemIcon>
        <ListItemText
          primary={
            <div>
              <div
                className={classes.bodyItem}
                style={{ width: dataColumns.definition_type.width }}
              >
                {node.definition_type}
              </div>
              <div
                className={classes.bodyItem}
                style={{ width: dataColumns.definition.width }}
              >
                {node.definition}
              </div>
              <div
                className={classes.bodyItem}
                style={{ width: dataColumns.x_opencti_color.width }}
              >
                {node.x_opencti_color}
              </div>
              <div
                className={classes.bodyItem}
                style={{ width: dataColumns.x_opencti_order.width }}
              >
                {node.x_opencti_order}
              </div>
              <div
                className={classes.bodyItem}
                style={{ width: dataColumns.created.width }}
              >
                {fd(node.created)}
              </div>
            </div>
          }
        />
        <ListItemSecondaryAction>
          <MarkingDefinitionPopover
            markingDefinitionId={node.id}
            paginationOptions={paginationOptions}
          />
        </ListItemSecondaryAction>
      </ListItem>
    );
  }
}

MarkingDefinitionLineComponent.propTypes = {
  dataColumns: PropTypes.object,
  node: PropTypes.object,
  paginationOptions: PropTypes.object,
  me: PropTypes.object,
  classes: PropTypes.object,
  fd: PropTypes.func,
};

const MarkingDefinitionLineFragment = createFragmentContainer(
  MarkingDefinitionLineComponent,
  {
    node: graphql`
      fragment MarkingDefinitionLine_node on MarkingDefinition {
        id
        definition_type
        definition
        x_opencti_order
        x_opencti_color
        created
        modified
      }
    `,
  },
);

export const MarkingDefinitionLine = compose(
  inject18n,
  withStyles(styles),
)(MarkingDefinitionLineFragment);

class MarkingDefinitionLineDummyComponent extends Component {
  render() {
    const { classes, dataColumns } = this.props;
    return (
      <ListItem classes={{ root: classes.item }} divider={true}>
        <ListItemIcon classes={{ root: classes.itemIconDisabled }}>
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
                style={{ width: dataColumns.definition_type.width }}
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
                style={{ width: dataColumns.definition.width }}
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
                style={{ width: dataColumns.x_opencti_color.width }}
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
                style={{ width: dataColumns.x_opencti_order.width }}
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

MarkingDefinitionLineDummyComponent.propTypes = {
  dataColumns: PropTypes.object,
  classes: PropTypes.object,
};

export const MarkingDefinitionLineDummy = compose(
  inject18n,
  withStyles(styles),
)(MarkingDefinitionLineDummyComponent);
