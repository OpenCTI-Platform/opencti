import React, { Component } from 'react';
import PropTypes from 'prop-types';
import { compose, propOr } from 'ramda';
import { createFragmentContainer } from 'react-relay';
import graphql from 'babel-plugin-relay/macro';
import { withStyles } from '@material-ui/core/styles';
import ListItem from '@material-ui/core/ListItem';
import ListItemIcon from '@material-ui/core/ListItemIcon';
import ListItemText from '@material-ui/core/ListItemText';
import Avatar from '@material-ui/core/Avatar'
import { MoreVert } from '@material-ui/icons';
import inject18n from '../../../components/i18n';

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
  avatar: {
    width: 24,
    height: 24,
    backgroundColor: theme.palette.primary.main
  },
});

const inlineStyles = {
  name: {
    float: 'left',
    width: '60%',
    whiteSpace: 'nowrap',
    overflow: 'hidden',
    textOverflow: 'ellipsis',
  },
  created_at: {
    float: 'left',
    width: '15%',
    whiteSpace: 'nowrap',
    overflow: 'hidden',
    textOverflow: 'ellipsis',
  },
  updated_at: {
    float: 'left',
    whiteSpace: 'nowrap',
    overflow: 'hidden',
    textOverflow: 'ellipsis',
  },
};

class ExternalReferenceLineComponent extends Component {
  render() {
    const {
      fd, classes, externalReference,
    } = this.props;
    return (
      <ListItem classes={{ default: classes.item }} divider={true}>
        <ListItemIcon classes={{ root: classes.itemIcon }}>
          <Avatar className={classes.avatar}>A</Avatar>
        </ListItemIcon>
        <ListItemText primary={
          <div>
            <div className={classes.bodyItem} style={inlineStyles.name}>
              {propOr('-', 'name', externalReference)}
            </div>
            <div className={classes.bodyItem} style={inlineStyles.created_at}>
              {fd(propOr(null, 'created_at', externalReference))}
            </div>
            <div className={classes.bodyItem} style={inlineStyles.updated_at}>
              {fd(propOr(null, 'updated_at', externalReference))}
            </div>
          </div>
        }/>
        <ListItemIcon classes={{ root: classes.goIcon }}>
          &nbsp;
        </ListItemIcon>
      </ListItem>
    );
  }
}

ExternalReferenceLineComponent.propTypes = {
  externalReference: PropTypes.object,
  paginationOptions: PropTypes.object,
  me: PropTypes.object,
  classes: PropTypes.object,
  fd: PropTypes.func,
};

const ExternalReferenceLineFragment = createFragmentContainer(ExternalReferenceLineComponent, {
  externalReference: graphql`
      fragment ExternalReferenceLine_externalReference on ExternalReference {
          id
          source_name
          description
          url
          hash
          external_id
      }
  `,
});

export const ExternalReferenceLine = compose(
  inject18n,
  withStyles(styles),
)(ExternalReferenceLineFragment);

class ExternalReferenceLineDummyComponent extends Component {
  render() {
    const { classes } = this.props;
    return (
      <ListItem classes={{ default: classes.item }} divider={true}>
        <ListItemIcon classes={{ root: classes.itemIconDisabled }}>
          <Avatar className={classes.avatar}>A</Avatar>
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

ExternalReferenceLineDummyComponent.propTypes = {
  classes: PropTypes.object,
};

export const ExternalReferenceLineDummy = compose(
  inject18n,
  withStyles(styles),
)(ExternalReferenceLineDummyComponent);
