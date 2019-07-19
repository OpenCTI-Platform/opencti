import React, { Component } from 'react';
import PropTypes from 'prop-types';
import { Link } from 'react-router-dom';
import { createFragmentContainer } from 'react-relay';
import graphql from 'babel-plugin-relay/macro';
import { withStyles } from '@material-ui/core/styles';
import ListItem from '@material-ui/core/ListItem';
import ListItemIcon from '@material-ui/core/ListItemIcon';
import ListItemText from '@material-ui/core/ListItemText';
import { KeyboardArrowRight, AccountBalance } from '@material-ui/icons';
import { compose } from 'ramda';
import inject18n from '../../../../components/i18n';

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
    color: theme.palette.grey[700],
  },
});

const inlineStyles = {
  name: {
    float: 'left',
    width: '40%',
    height: 20,
    whiteSpace: 'nowrap',
    overflow: 'hidden',
    textOverflow: 'ellipsis',
  },
  organization_class: {
    float: 'left',
    width: '20%',
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

class OrganizationLineComponent extends Component {
  render() {
    const {
      t, fd, classes, organization,
    } = this.props;
    return (
      <ListItem
        classes={{ root: classes.item }}
        divider={true}
        component={Link}
        to={`/dashboard/entities/organizations/${organization.id}`}
      >
        <ListItemIcon classes={{ root: classes.itemIcon }}>
          <AccountBalance />
        </ListItemIcon>
        <ListItemText
          primary={
            <div>
              <div className={classes.bodyItem} style={inlineStyles.name}>
                {organization.name}
              </div>
              <div className={classes.bodyItem} style={inlineStyles.organization_class}>
                {organization.organization_class ? t(`organization_${organization.organization_class}`) : ''}
              </div>
              <div className={classes.bodyItem} style={inlineStyles.created}>
                {fd(organization.created)}
              </div>
              <div className={classes.bodyItem} style={inlineStyles.modified}>
                {fd(organization.modified)}
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

OrganizationLineComponent.propTypes = {
  organization: PropTypes.object,
  classes: PropTypes.object,
  fd: PropTypes.func,
};

const OrganizationLineFragment = createFragmentContainer(
  OrganizationLineComponent,
  {
    organization: graphql`
      fragment OrganizationLine_organization on Organization {
        id
        organization_class
        name
        created
        modified
      }
    `,
  },
);

export const OrganizationLine = compose(
  inject18n,
  withStyles(styles),
)(OrganizationLineFragment);

class OrganizationLineDummyComponent extends Component {
  render() {
    const { classes } = this.props;
    return (
      <ListItem classes={{ root: classes.item }} divider={true}>
        <ListItemIcon classes={{ root: classes.itemIconDisabled }}>
          <AccountBalance />
        </ListItemIcon>
        <ListItemText
          primary={
            <div>
              <div className={classes.bodyItem} style={inlineStyles.name}>
                <div className="fakeItem" style={{ width: '80%' }} />
              </div>
              <div className={classes.bodyItem} style={inlineStyles.organization_class}>
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

OrganizationLineDummyComponent.propTypes = {
  classes: PropTypes.object,
};

export const OrganizationLineDummy = compose(
  inject18n,
  withStyles(styles),
)(OrganizationLineDummyComponent);
