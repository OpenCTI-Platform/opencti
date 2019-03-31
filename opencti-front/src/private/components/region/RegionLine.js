import React, { Component } from 'react';
import PropTypes from 'prop-types';
import { Link } from 'react-router-dom';
import { createFragmentContainer } from 'react-relay';
import graphql from 'babel-plugin-relay/macro';
import { withStyles } from '@material-ui/core/styles';
import ListItem from '@material-ui/core/ListItem';
import ListItemIcon from '@material-ui/core/ListItemIcon';
import ListItemText from '@material-ui/core/ListItemText';
import { KeyboardArrowRight, Map } from '@material-ui/icons';
import { compose } from 'ramda';
import inject18n from '../../../components/i18n';

const styles = theme => ({
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
    fontSize: 13,
  },
  goIcon: {
    position: 'absolute',
    right: 10,
    marginRight: 0,
  },
  itemIconDisabled: {
    color: theme.palette.text.disabled,
  },
  placeholder: {
    display: 'inline-block',
    height: '1em',
    backgroundColor: theme.palette.text.disabled,
  },
});

const inlineStyles = {
  name: {
    float: 'left',
    width: '60%',
    height: 20,
    whiteSpace: 'nowrap',
    overflow: 'hidden',
    textOverflow: 'ellipsis',
  },
  created: {
    float: 'left',
    width: '15%',
    height: 20,
    whiteSpace: 'nowrap',
    overflow: 'hidden',
    textOverflow: 'ellipsis',
  },
  modified: {
    float: 'left',
    height: 20,
    whiteSpace: 'nowrap',
    overflow: 'hidden',
    textOverflow: 'ellipsis',
  },
};

class RegionLineComponent extends Component {
  render() {
    const { fd, classes, region } = this.props;
    return (
      <ListItem
        classes={{ default: classes.item }}
        divider={true}
        component={Link}
        to={`/dashboard/catalogs/regions/${region.id}`}
      >
        <ListItemIcon classes={{ root: classes.itemIcon }}>
          <Map />
        </ListItemIcon>
        <ListItemText
          primary={
            <div>
              <div className={classes.bodyItem} style={inlineStyles.name}>
                {region.name}
              </div>
              <div className={classes.bodyItem} style={inlineStyles.created}>
                {fd(region.created)}
              </div>
              <div className={classes.bodyItem} style={inlineStyles.modified}>
                {fd(region.modified)}
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

RegionLineComponent.propTypes = {
  region: PropTypes.object,
  classes: PropTypes.object,
  fd: PropTypes.func,
};

const RegionLineFragment = createFragmentContainer(RegionLineComponent, {
  region: graphql`
    fragment RegionLine_region on Region {
      id
      name
      created
      modified
    }
  `,
});

export const RegionLine = compose(
  inject18n,
  withStyles(styles),
)(RegionLineFragment);

class RegionLineDummyComponent extends Component {
  render() {
    const { classes } = this.props;
    return (
      <ListItem classes={{ default: classes.item }} divider={true}>
        <ListItemIcon classes={{ root: classes.itemIconDisabled }}>
          <Map />
        </ListItemIcon>
        <ListItemText
          primary={
            <div>
              <div className={classes.bodyItem} style={inlineStyles.name}>
                <div className="fakeItem" style={{ width: '80%' }} />
              </div>
              <div className={classes.bodyItem} style={inlineStyles.created}>
                <div className="fakeItem" style={{ width: 140 }} />
              </div>
              <div className={classes.bodyItem} style={inlineStyles.modified}>
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

RegionLineDummyComponent.propTypes = {
  classes: PropTypes.object,
};

export const RegionLineDummy = compose(
  inject18n,
  withStyles(styles),
)(RegionLineDummyComponent);
