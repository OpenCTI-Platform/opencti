import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import { compose } from 'ramda';
import { createFragmentContainer } from 'react-relay';
import graphql from 'babel-plugin-relay/macro';
import { withStyles } from '@material-ui/core/styles';
import ListItem from '@material-ui/core/ListItem';
import ListItemIcon from '@material-ui/core/ListItemIcon';
import ListItemText from '@material-ui/core/ListItemText';
import { MoreVert, AccountBalance } from '@material-ui/icons';
import inject18n from '../../../components/i18n';
import OrganizationPopover from './OrganizationPopover';

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

class OrganizationLineComponent extends Component {
  render() {
    const {
      fd, classes, organization, paginationOptions,
    } = this.props;
    return (
      <ListItem classes={{ default: classes.item }} divider={true}>
        <ListItemIcon classes={{ root: classes.itemIcon }}>
          <AccountBalance/>
        </ListItemIcon>
        <ListItemText primary={
          <div>
            <div className={classes.bodyItem} style={inlineStyles.name}>
              {organization.name}
            </div>
            <div className={classes.bodyItem} style={inlineStyles.created_at}>
              {fd(organization.created_at)}
            </div>
            <div className={classes.bodyItem} style={inlineStyles.updated_at}>
              {fd(organization.updated_at)}
            </div>
          </div>
        }/>
        <ListItemIcon classes={{ root: classes.goIcon }}>
          <OrganizationPopover organizationId={organization.id} paginationOptions={paginationOptions}/>
        </ListItemIcon>
      </ListItem>
    );
  }
}

OrganizationLineComponent.propTypes = {
  organization: PropTypes.object,
  paginationOptions: PropTypes.object,
  me: PropTypes.object,
  classes: PropTypes.object,
  fd: PropTypes.func,
};

const OrganizationLineFragment = createFragmentContainer(OrganizationLineComponent, {
  organization: graphql`
      fragment OrganizationLine_organization on Organization {
          id
          name
          created_at
          updated_at
      }
  `,
});

export const OrganizationLine = compose(
  inject18n,
  withStyles(styles),
)(OrganizationLineFragment);

class OrganizationLineDummyComponent extends Component {
  render() {
    const { classes } = this.props;
    return (
      <ListItem classes={{ default: classes.item }} divider={true}>
        <ListItemIcon classes={{ root: classes.itemIconDisabled }}>
          <AccountBalance/>
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

OrganizationLineDummyComponent.propTypes = {
  classes: PropTypes.object,
};

export const OrganizationLineDummy = compose(
  inject18n,
  withStyles(styles),
)(OrganizationLineDummyComponent);
