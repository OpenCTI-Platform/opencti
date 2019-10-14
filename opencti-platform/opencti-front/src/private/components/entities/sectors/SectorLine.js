import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import { Link } from 'react-router-dom';
import { withStyles } from '@material-ui/core/styles';
import ListItem from '@material-ui/core/ListItem';
import ListItemIcon from '@material-ui/core/ListItemIcon';
import ListItemText from '@material-ui/core/ListItemText';
import { KeyboardArrowRight, Domain } from '@material-ui/icons';
import { compose, map } from 'ramda';
import List from '@material-ui/core/List';
import inject18n from '../../../../components/i18n';

const styles = theme => ({
  item: {},
  itemNested: {
    paddingLeft: theme.spacing(4),
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
    height: '.6em',
    backgroundColor: theme.palette.grey[700],
  },
});

class SectorLineComponent extends Component {
  render() {
    const {
      classes, subsectors, node, isSubsector,
    } = this.props;
    return (
      <div>
        <ListItem
          classes={{ root: isSubsector ? classes.itemNested : classes.item }}
          divider={true}
          dense={true}
          button={true}
          component={Link}
          to={`/dashboard/entities/sectors/${node.id}`}
        >
          <ListItemIcon classes={{ root: classes.itemIcon }}>
            <Domain />
          </ListItemIcon>
          <ListItemText primary={node.name} secondary={node.description} />
          <ListItemIcon classes={{ root: classes.goIcon }}>
            <KeyboardArrowRight />
          </ListItemIcon>
        </ListItem>
        {subsectors ? (
          <List disablePadding={true}>
            {map(
              subsector => (
                <SectorLine
                  key={subsector.id}
                  node={subsector}
                  isSubsector={true}
                />
              ),
              subsectors,
            )}
          </List>
        ) : (
          ''
        )}
      </div>
    );
  }
}

SectorLineComponent.propTypes = {
  node: PropTypes.object,
  isSubsector: PropTypes.bool,
  subsectors: PropTypes.array,
  classes: PropTypes.object,
  fd: PropTypes.func,
};

export const SectorLine = compose(
  inject18n,
  withStyles(styles),
)(SectorLineComponent);

class SectorLineDummyComponent extends Component {
  render() {
    const { classes } = this.props;
    return (
      <ListItem classes={{ root: classes.item }} divider={true} dense={true}>
        <ListItemIcon classes={{ root: classes.itemIconDisabled }}>
          <Domain />
        </ListItemIcon>
        <ListItemText
          primary={<span className="fakeItem" style={{ width: '80%' }} />}
          secondary={<span className="fakeItem" style={{ width: '90%' }} />}
        />
        <ListItemIcon classes={{ root: classes.goIcon }}>
          <KeyboardArrowRight />
        </ListItemIcon>
      </ListItem>
    );
  }
}

SectorLineDummyComponent.propTypes = {
  classes: PropTypes.object,
};

export const SectorLineDummy = compose(
  inject18n,
  withStyles(styles),
)(SectorLineDummyComponent);
