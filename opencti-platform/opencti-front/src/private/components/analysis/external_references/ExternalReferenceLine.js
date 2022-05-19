import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import { graphql, createFragmentContainer } from 'react-relay';
import withStyles from '@mui/styles/withStyles';
import ListItem from '@mui/material/ListItem';
import ListItemIcon from '@mui/material/ListItemIcon';
import ListItemText from '@mui/material/ListItemText';
import ListItemSecondaryAction from '@mui/material/ListItemSecondaryAction';
import {
  LanguageOutlined,
  KeyboardArrowRightOutlined,
} from '@mui/icons-material';
import { compose } from 'ramda';
import Skeleton from '@mui/material/Skeleton';
import { Link } from 'react-router-dom';
import Tooltip from '@mui/material/Tooltip';
import inject18n from '../../../../components/i18n';

const styles = (theme) => ({
  item: {
    paddingLeft: 10,
    height: 50,
    cursor: 'pointer',
  },
  itemIcon: {
    color: theme.palette.primary.main,
  },
  avatar: {
    width: 24,
    height: 24,
    backgroundColor: theme.palette.primary.main,
  },
  avatarDisabled: {
    width: 24,
    height: 24,
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

class ExternalReferenceLineComponent extends Component {
  render() {
    const { fd, classes, dataColumns, node } = this.props;
    return (
      <ListItem
        classes={{ root: classes.item }}
        divider={true}
        button={true}
        component={Link}
        to={`/dashboard/analysis/external_references/${node.id}`}
      >
        <ListItemIcon classes={{ root: classes.itemIcon }}>
          <LanguageOutlined />
        </ListItemIcon>
        <ListItemText
          primary={
            <div>
              <div
                className={classes.bodyItem}
                style={{ width: dataColumns.source_name.width }}
              >
                {node.source_name}
              </div>
              <div
                className={classes.bodyItem}
                style={{ width: dataColumns.external_id.width }}
              >
                {node.external_id}
              </div>
              <Tooltip title={node.url}>
                <div
                  className={classes.bodyItem}
                  style={{ width: dataColumns.url.width }}
                >
                  {node.url}
                </div>
              </Tooltip>
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
          <KeyboardArrowRightOutlined />
        </ListItemSecondaryAction>
      </ListItem>
    );
  }
}

ExternalReferenceLineComponent.propTypes = {
  dataColumns: PropTypes.object,
  node: PropTypes.object,
  paginationOptions: PropTypes.object,
  me: PropTypes.object,
  classes: PropTypes.object,
  fd: PropTypes.func,
};

const ExternalReferenceLineFragment = createFragmentContainer(
  ExternalReferenceLineComponent,
  {
    node: graphql`
      fragment ExternalReferenceLine_node on ExternalReference {
        id
        source_name
        external_id
        url
        created
      }
    `,
  },
);

export const ExternalReferenceLine = compose(
  inject18n,
  withStyles(styles),
)(ExternalReferenceLineFragment);

class ExternalReferenceLineDummyComponent extends Component {
  render() {
    const { classes, dataColumns } = this.props;
    return (
      <ListItem classes={{ root: classes.item }} divider={true}>
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
                style={{ width: dataColumns.source_name.width }}
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
                style={{ width: dataColumns.external_id.width }}
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
                style={{ width: dataColumns.url.width }}
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
                  width={140}
                  height="100%"
                />
              </div>
            </div>
          }
        />
        <ListItemSecondaryAction classes={{ root: classes.itemIconDisabled }}>
          <KeyboardArrowRightOutlined />
        </ListItemSecondaryAction>
      </ListItem>
    );
  }
}

ExternalReferenceLineDummyComponent.propTypes = {
  dataColumns: PropTypes.object,
  classes: PropTypes.object,
};

export const ExternalReferenceLineDummy = compose(
  inject18n,
  withStyles(styles),
)(ExternalReferenceLineDummyComponent);
