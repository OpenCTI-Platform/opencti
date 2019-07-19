import React, { Component } from 'react';
import PropTypes from 'prop-types';
import { Link } from 'react-router-dom';
import { createFragmentContainer } from 'react-relay';
import graphql from 'babel-plugin-relay/macro';
import { withStyles } from '@material-ui/core/styles';
import ListItem from '@material-ui/core/ListItem';
import ListItemIcon from '@material-ui/core/ListItemIcon';
import ListItemText from '@material-ui/core/ListItemText';
import { KeyboardArrowRight } from '@material-ui/icons';
import { Fire } from 'mdi-material-ui';
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
  placeholder: {
    display: 'inline-block',
    height: '1em',
    backgroundColor: theme.palette.grey[700],
  },
});

const inlineStyles = {
  name: {
    float: 'left',
    width: '70%',
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

class IncidentLineComponent extends Component {
  render() {
    const { fd, classes, incident } = this.props;
    return (
      <ListItem
        classes={{ root: classes.item }}
        divider={true}
        component={Link}
        to={`/dashboard/threats/incidents/${incident.id}`}
      >
        <ListItemIcon classes={{ root: classes.itemIcon }}>
          <Fire />
        </ListItemIcon>
        <ListItemText
          primary={
            <div>
              <div className={classes.bodyItem} style={inlineStyles.name}>
                {incident.name}
              </div>
              <div className={classes.bodyItem} style={inlineStyles.created}>
                {fd(incident.created)}
              </div>
              <div className={classes.bodyItem} style={inlineStyles.modified}>
                {fd(incident.modified)}
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

IncidentLineComponent.propTypes = {
  incident: PropTypes.object,
  classes: PropTypes.object,
  fd: PropTypes.func,
};

const IncidentLineFragment = createFragmentContainer(IncidentLineComponent, {
  incident: graphql`
    fragment IncidentLine_incident on Incident {
      id
      name
      created
      modified
    }
  `,
});

export const IncidentLine = compose(
  inject18n,
  withStyles(styles),
)(IncidentLineFragment);

class IncidentLineDummyComponent extends Component {
  render() {
    const { classes } = this.props;
    return (
      <ListItem classes={{ root: classes.item }} divider={true}>
        <ListItemIcon classes={{ root: classes.itemIconDisabled }}>
          <Fire />
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

IncidentLineDummyComponent.propTypes = {
  classes: PropTypes.object,
};

export const IncidentLineDummy = compose(
  inject18n,
  withStyles(styles),
)(IncidentLineDummyComponent);
