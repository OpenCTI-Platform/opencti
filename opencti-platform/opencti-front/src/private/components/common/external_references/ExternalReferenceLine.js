import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import { createFragmentContainer } from 'react-relay';
import graphql from 'babel-plugin-relay/macro';
import { withStyles } from '@material-ui/core/styles';
import ListItem from '@material-ui/core/ListItem';
import ListItemIcon from '@material-ui/core/ListItemIcon';
import ListItemText from '@material-ui/core/ListItemText';
import Avatar from '@material-ui/core/Avatar';
import { MoreVert } from '@material-ui/icons';
import { compose } from 'ramda';
import inject18n from '../../../../components/i18n';
import ExternalReferencePopover from './ExternalReferencePopover';

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
  placeholder: {
    display: 'inline-block',
    height: '1em',
    backgroundColor: theme.palette.grey[700],
  },
});

const inlineStyles = {
  source_name: {
    float: 'left',
    width: '15%',
    height: 20,
    whiteSpace: 'nowrap',
    overflow: 'hidden',
    textOverflow: 'ellipsis',
  },
  external_id: {
    float: 'left',
    width: '10%',
    height: 20,
    whiteSpace: 'nowrap',
    overflow: 'hidden',
    textOverflow: 'ellipsis',
  },
  url: {
    float: 'left',
    width: '50%',
    height: 20,
    whiteSpace: 'nowrap',
    overflow: 'hidden',
    textOverflow: 'ellipsis',
  },
  created: {
    float: 'left',
    height: 20,
    whiteSpace: 'nowrap',
    overflow: 'hidden',
    textOverflow: 'ellipsis',
  },
};

class ExternalReferenceLineComponent extends Component {
  render() {
    const {
      fd, classes, externalReference, paginationOptions,
    } = this.props;
    return (
      <ListItem classes={{ root: classes.item }} divider={true}>
        <ListItemIcon classes={{ root: classes.itemIcon }}>
          <Avatar classes={{ root: classes.avatar }}>
            {externalReference.source_name.substring(0, 1)}
          </Avatar>
        </ListItemIcon>
        <ListItemText
          primary={
            <div>
              <div
                className={classes.bodyItem}
                style={inlineStyles.source_name}
              >
                {externalReference.source_name}
              </div>
              <div
                className={classes.bodyItem}
                style={inlineStyles.external_id}
              >
                {externalReference.external_id}
              </div>
              <div className={classes.bodyItem} style={inlineStyles.url}>
                {externalReference.url}
              </div>
              <div className={classes.bodyItem} style={inlineStyles.created}>
                {fd(externalReference.created)}
              </div>
            </div>
          }
        />
        <ListItemIcon classes={{ root: classes.goIcon }}>
          <ExternalReferencePopover
            externalReferenceId={externalReference.id}
            paginationOptions={paginationOptions}
          />
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

const ExternalReferenceLineFragment = createFragmentContainer(
  ExternalReferenceLineComponent,
  {
    externalReference: graphql`
      fragment ExternalReferenceLine_externalReference on ExternalReference {
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
    const { classes } = this.props;
    return (
      <ListItem classes={{ root: classes.item }} divider={true}>
        <ListItemIcon classes={{ root: classes.itemIconDisabled }}>
          <Avatar classes={{ root: classes.avatarDisabled }}>A</Avatar>
        </ListItemIcon>
        <ListItemText
          primary={
            <div>
              <div
                className={classes.bodyItem}
                style={inlineStyles.source_name}
              >
                <div className="fakeItem" style={{ width: '80%' }} />
              </div>
              <div
                className={classes.bodyItem}
                style={inlineStyles.external_id}
              >
                <div className="fakeItem" style={{ width: '70%' }} />
              </div>
              <div className={classes.bodyItem} style={inlineStyles.url}>
                <div className="fakeItem" style={{ width: '60%' }} />
              </div>
              <div className={classes.bodyItem} style={inlineStyles.created}>
                <div className="fakeItem" style={{ width: 140 }} />
              </div>
            </div>
          }
        />
        <ListItemIcon classes={{ root: classes.goIcon }}>
          <MoreVert />
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
