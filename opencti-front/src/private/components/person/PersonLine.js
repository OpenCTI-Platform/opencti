import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import { compose, includes, propOr } from 'ramda';
import { createFragmentContainer } from 'react-relay';
import graphql from 'babel-plugin-relay/macro';
import { withStyles } from '@material-ui/core/styles';
import ListItem from '@material-ui/core/ListItem';
import ListItemIcon from '@material-ui/core/ListItemIcon';
import ListItemText from '@material-ui/core/ListItemText';
import { MoreVert, Person } from '@material-ui/icons';
import inject18n from '../../../components/i18n';
import PersonPopover from './PersonPopover';

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

class PersonLineComponent extends Component {
  render() {
    const {
      fd, classes, person, me, paginationOptions,
    } = this.props;
    return (
      <ListItem classes={{ default: classes.item }} divider={true}>
        <ListItemIcon classes={{ root: classes.itemIcon }}>
          <Person />
        </ListItemIcon>
        <ListItemText
          primary={
            <div>
              <div className={classes.bodyItem} style={inlineStyles.name}>
                {person.name}
              </div>
              <div className={classes.bodyItem} style={inlineStyles.created_at}>
                {fd(person.created_at)}
              </div>
              <div className={classes.bodyItem} style={inlineStyles.updated_at}>
                {fd(person.updated_at)}
              </div>
            </div>
          }
        />
        <ListItemIcon classes={{ root: classes.goIcon }}>
          <PersonPopover
            personId={person.id}
            paginationOptions={paginationOptions}
            disabled={!includes('ROLE_ADMIN', propOr([], 'grant', me))}
          />
        </ListItemIcon>
      </ListItem>
    );
  }
}

PersonLineComponent.propTypes = {
  person: PropTypes.object,
  paginationOptions: PropTypes.object,
  me: PropTypes.object,
  classes: PropTypes.object,
  fd: PropTypes.func,
};

const PersonLineFragment = createFragmentContainer(PersonLineComponent, {
  person: graphql`
    fragment PersonLine_person on User {
      id
      name
      created_at
      updated_at
    }
  `,
  me: graphql`
    fragment PersonLine_me on User {
      grant
    }
  `,
});

export const PersonLine = compose(
  inject18n,
  withStyles(styles),
)(PersonLineFragment);

class PersonLineDummyComponent extends Component {
  render() {
    const { classes } = this.props;
    return (
      <ListItem classes={{ default: classes.item }} divider={true}>
        <ListItemIcon classes={{ root: classes.itemIconDisabled }}>
          <Person />
        </ListItemIcon>
        <ListItemText
          primary={
            <div>
              <div className={classes.bodyItem} style={inlineStyles.name}>
                <div className='fakeItem' style={{ width: '80%' }} />
              </div>
              <div className={classes.bodyItem} style={inlineStyles.created_at}>
                <div className='fakeItem' style={{ width: 80 }} />
              </div>
              <div className={classes.bodyItem} style={inlineStyles.updated_at}>
                <div className='fakeItem' style={{ width: 80 }} />
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

PersonLineDummyComponent.propTypes = {
  classes: PropTypes.object,
};

export const PersonLineDummy = compose(
  inject18n,
  withStyles(styles),
)(PersonLineDummyComponent);
