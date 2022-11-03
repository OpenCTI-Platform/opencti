import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import { compose } from 'ramda';
import { Link } from 'react-router-dom';
import { createFragmentContainer } from 'react-relay';
import graphql from 'babel-plugin-relay/macro';
import { withStyles } from '@material-ui/core/styles';
import ListItem from '@material-ui/core/ListItem';
import ListItemIcon from '@material-ui/core/ListItemIcon';
import PlayArrowIcon from '@material-ui/icons/PlayArrow';
import ListItemSecondaryAction from '@material-ui/core/ListItemSecondaryAction';
import Checkbox from '@material-ui/core/Checkbox';
import { Button } from '@material-ui/core';
import ListItemText from '@material-ui/core/ListItemText';
import Skeleton from '@material-ui/lab/Skeleton';
import inject18n from '../../../../../components/i18n';
import CyioCoreObjectLabels from '../../../common/stix_core_objects/CyioCoreObjectLabels';
import DataSourcesPopover from './DataSourcesPopover';
import resetIcon from '../../../../../resources/images/dataSources/resetIcon.svg';
import clearAllIcon from '../../../../../resources/images/dataSources/clearAllIcon.svg';
import startIcon from '../../../../../resources/images/dataSources/startIcon.svg';
import stopIcon from '../../../../../resources/images/dataSources/stopIcon.svg';

const styles = (theme) => ({
  item: {
    '&.Mui-selected, &.Mui-selected:hover': {
      backgroundColor: theme.palette.navAlt.background,
    },
    paddingLeft: 10,
    height: 50,
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
    display: 'flex',
  },
  btnIcons: {
    minHeight: '2rem',
    margin: '0.8em 1em 1em 0',
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

class DataSourceLineComponent extends Component {
  render() {
    const {
      t,
      fd,
      classes,
      history,
      node,
      selectAll,
      dataColumns,
      onLabelClick,
      onToggleEntity,
      selectedElements,
    } = this.props;
    return (
      <ListItem
        classes={{ root: classes.item }}
        divider={true}
        button={true}
        component={Link}
        selected={selectAll || node.id in (selectedElements || {})}
        to={`/data/data source/${node.id}`}
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
                style={{ width: dataColumns.name.width }}
              >
                {node.name && t(node.name)}
              </div>
              <div
                className={classes.bodyItem}
                style={{ width: dataColumns.type.width }}
              >
                {node.entity_type && t(node.entity_type)}
              </div>
              <div
                className={classes.bodyItem}
                style={{ width: '16.5%' }}
              >
                <CyioCoreObjectLabels
                  variant="inList"
                  labels={node.labels}
                  onClick={onLabelClick.bind(this)}
                />
              </div>
              <div
                className={classes.bodyItem}
                style={{ width: '21%' }}
              >
                <CyioCoreObjectLabels
                  variant="inList"
                  labels={node.labels}
                  onClick={onLabelClick.bind(this)}
                />
              </div>
              <div
                className={classes.bodyItem}
                style={{ width: dataColumns.trigger.width }}
              >
                {node.created && fd(node.created)}
              </div>
              <div
                className={classes.bodyItem}
                style={{ width: dataColumns.count.width }}
              >
                {/* {node?.parent_types && t(node.parent_types)} */}
              </div>
            </div>
          }
        />
        <ListItemSecondaryAction classes={{ root: classes.goIcon }}>
          <Button color='primary' variant='contained' className={classes.btnIcons}>
            <img src={startIcon} />
          </Button>
          <Button color='primary' variant='contained' className={classes.btnIcons}>
            <img src={resetIcon} />
          </Button>
          <Button color='primary' variant='contained' className={classes.btnIcons}>
            <img src={clearAllIcon} />
          </Button>
          <DataSourcesPopover
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

DataSourceLineComponent.propTypes = {
  dataColumns: PropTypes.object,
  node: PropTypes.object,
  history: PropTypes.object,
  classes: PropTypes.object,
  fd: PropTypes.func,
  t: PropTypes.func,
  onLabelClick: PropTypes.func,
};

const DataSourceLineFragment = createFragmentContainer(
  DataSourceLineComponent,
  {
    node: graphql`
      fragment DataSourceLine_node on OscalLocation {
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

export const DataSourceLine = compose(
  inject18n,
  withStyles(styles),
)(DataSourceLineFragment);

class DataSourceLineDummyComponent extends Component {
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
                  width="90%"
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
                  width="90%"
                  height="100%"
                />
              </div>
              <div
                className={classes.bodyItem}
                style={{ width: dataColumns.trigger.width }}
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
                style={{ width: dataColumns.count.width }}
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

DataSourceLineDummyComponent.propTypes = {
  classes: PropTypes.object,
  dataColumns: PropTypes.object,
};

export const DataSourceLineDummy = compose(
  inject18n,
  withStyles(styles),
)(DataSourceLineDummyComponent);
