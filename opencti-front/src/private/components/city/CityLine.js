import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import { compose } from 'ramda';
import { createFragmentContainer } from 'react-relay';
import graphql from 'babel-plugin-relay/macro';
import { withStyles } from '@material-ui/core/styles';
import ListItem from '@material-ui/core/ListItem';
import ListItemIcon from '@material-ui/core/ListItemIcon';
import ListItemText from '@material-ui/core/ListItemText';
import { MoreVert } from '@material-ui/icons';
import { CityVariant } from 'mdi-material-ui';
import inject18n from '../../../components/i18n';
import CityPopover from './CityPopover';

const styles = theme => ({
  item: {
    paddingLeft: 10,
    transition: 'background-color 0.1s ease',
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
  created_at: {
    float: 'left',
    width: '15%',
    height: 20,
    whiteSpace: 'nowrap',
    overflow: 'hidden',
    textOverflow: 'ellipsis',
  },
  updated_at: {
    float: 'left',
    height: 20,
    whiteSpace: 'nowrap',
    overflow: 'hidden',
    textOverflow: 'ellipsis',
  },
};

class CityLineComponent extends Component {
  render() {
    const {
      fd, classes, city, paginationOptions,
    } = this.props;
    return (
      <ListItem classes={{ default: classes.item }} divider={true}>
        <ListItemIcon classes={{ root: classes.itemIcon }}>
          <CityVariant/>
        </ListItemIcon>
        <ListItemText primary={
          <div>
            <div className={classes.bodyItem} style={inlineStyles.name}>
              {city.name}
            </div>
            <div className={classes.bodyItem} style={inlineStyles.created_at}>
              {fd(city.created_at)}
            </div>
            <div className={classes.bodyItem} style={inlineStyles.updated_at}>
              {fd(city.updated_at)}
            </div>
          </div>
        }/>
        <ListItemIcon classes={{ root: classes.goIcon }}>
          <CityPopover cityId={city.id} paginationOptions={paginationOptions}/>
        </ListItemIcon>
      </ListItem>
    );
  }
}

CityLineComponent.propTypes = {
  city: PropTypes.object,
  paginationOptions: PropTypes.object,
  me: PropTypes.object,
  classes: PropTypes.object,
  fd: PropTypes.func,
};

const CityLineFragment = createFragmentContainer(CityLineComponent, {
  city: graphql`
      fragment CityLine_city on City {
          id
          name
          created_at
          updated_at
      }
  `,
});

export const CityLine = compose(
  inject18n,
  withStyles(styles),
)(CityLineFragment);

class CityLineDummyComponent extends Component {
  render() {
    const { classes } = this.props;
    return (
      <ListItem classes={{ default: classes.item }} divider={true}>
        <ListItemIcon classes={{ root: classes.itemIconDisabled }}>
          <CityVariant/>
        </ListItemIcon>
        <ListItemText primary={
          <div>
            <div className={classes.bodyItem} style={inlineStyles.name}>
              <div className={classes.placeholder} style={{ width: '80%' }}/>
            </div>
            <div className={classes.bodyItem} style={inlineStyles.created_at}>
              <div className={classes.placeholder} style={{ width: 80 }}/>
            </div>
            <div className={classes.bodyItem} style={inlineStyles.updated_at}>
              <div className={classes.placeholder} style={{ width: 80 }}/>
            </div>
          </div>
        }/>
        <ListItemIcon classes={{ root: classes.goIcon }}>
          <MoreVert/>
        </ListItemIcon>
      </ListItem>
    );
  }
}

CityLineDummyComponent.propTypes = {
  classes: PropTypes.object,
};

export const CityLineDummy = compose(
  inject18n,
  withStyles(styles),
)(CityLineDummyComponent);
