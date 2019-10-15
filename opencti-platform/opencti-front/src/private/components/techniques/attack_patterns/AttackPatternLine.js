import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import {
  compose, pipe, pathOr, join, map, sort,
} from 'ramda';
import { Link } from 'react-router-dom';
import { createFragmentContainer } from 'react-relay';
import graphql from 'babel-plugin-relay/macro';
import { withStyles } from '@material-ui/core/styles';
import ListItem from '@material-ui/core/ListItem';
import ListItemIcon from '@material-ui/core/ListItemIcon';
import ListItemText from '@material-ui/core/ListItemText';
import { KeyboardArrowRight } from '@material-ui/icons';
import { LockPattern } from 'mdi-material-ui';
import inject18n from '../../../../components/i18n';
import StixObjectTags from '../../common/stix_object/StixObjectTags';

const styles = (theme) => ({
  item: {
    paddingLeft: 10,
    transition: 'background-color 0.1s ease',
    cursor: 'pointer',
    '&:hover': {
      background: 'rgba(0, 0, 0, 0.1)',
    },
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

class AttackPatternLineComponent extends Component {
  render() {
    const {
      fd, classes, node, dataColumns, orderAsc, onTagClick,
    } = this.props;
    const killchainPhases = pipe(
      pathOr([], ['killChainPhases', 'edges']),
      map((n) => n.node.phase_name),
      sort((a, b) => (orderAsc ? a.localeCompare(b) : b.localeCompare(a))),
      join(', '),
    )(node);
    return (
      <ListItem
        classes={{ root: classes.item }}
        divider={true}
        component={Link}
        to={`/dashboard/techniques/attack_patterns/${node.id}`}
      >
        <ListItemIcon classes={{ root: classes.itemIcon }}>
          <LockPattern />
        </ListItemIcon>
        <ListItemText
          primary={
            <div>
              <div
                className={classes.bodyItem}
                style={{ width: dataColumns.killChainPhases.width }}
              >
                {killchainPhases}
              </div>
              <div
                className={classes.bodyItem}
                style={{ width: dataColumns.name.width }}
              >
                {node.name}
              </div>
              <div
                className={classes.bodyItem}
                style={{ width: dataColumns.tags.width }}
              >
                <StixObjectTags
                  variant="inList"
                  tags={node.tags}
                  onClick={onTagClick.bind(this)}
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
                style={{ width: dataColumns.modified.width }}
              >
                {fd(node.modified)}
              </div>
            </div>
          }
        />
        <ListItemIcon classes={{ root: classes.goIcon }}>
          <KeyboardArrowRight />
        </ListItemIcon>
      </ListItem>
    );
  }
}

AttackPatternLineComponent.propTypes = {
  dataColumns: PropTypes.object,
  node: PropTypes.object,
  classes: PropTypes.object,
  fd: PropTypes.func,
  orderAsc: PropTypes.bool,
  onTagClick: PropTypes.func,
};

const AttackPatternLineFragment = createFragmentContainer(
  AttackPatternLineComponent,
  {
    node: graphql`
      fragment AttackPatternLine_node on AttackPattern {
        id
        name
        created
        modified
        killChainPhases {
          edges {
            node {
              id
              kill_chain_name
              phase_name
            }
          }
        }
        tags {
          edges {
            node {
              id
              tag_type
              value
              color
            }
            relation {
              id
            }
          }
        }
      }
    `,
  },
);

export const AttackPatternLine = compose(
  inject18n,
  withStyles(styles),
)(AttackPatternLineFragment);

class AttackPatternLineDummyComponent extends Component {
  render() {
    const { classes, dataColumns } = this.props;
    return (
      <ListItem classes={{ root: classes.item }} divider={true}>
        <ListItemIcon classes={{ root: classes.itemIconDisabled }}>
          <LockPattern />
        </ListItemIcon>
        <ListItemText
          primary={
            <div>
              <div
                className={classes.bodyItem}
                style={{ width: dataColumns.killChainPhases.width }}
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
                style={{ width: dataColumns.tags.width }}
              >
                <div className="fakeItem" style={{ width: '90%' }} />
              </div>
              <div
                className={classes.bodyItem}
                style={{ width: dataColumns.created.width }}
              >
                <div className="fakeItem" style={{ width: 140 }} />
              </div>
              <div
                className={classes.bodyItem}
                style={{ width: dataColumns.modified.width }}
              >
                <div className="fakeItem" style={{ width: 140 }} />
              </div>
            </div>
          }
        />
        <ListItemIcon classes={{ root: classes.goIcon }}>
          <KeyboardArrowRight />
        </ListItemIcon>
      </ListItem>
    );
  }
}

AttackPatternLineDummyComponent.propTypes = {
  dataColumns: PropTypes.object,
  classes: PropTypes.object,
};

export const AttackPatternLineDummy = compose(
  inject18n,
  withStyles(styles),
)(AttackPatternLineDummyComponent);
