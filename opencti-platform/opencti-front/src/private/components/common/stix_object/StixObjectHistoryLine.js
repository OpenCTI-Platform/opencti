import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import { compose, join } from 'ramda';
import { Link } from 'react-router-dom';
import { createFragmentContainer } from 'react-relay';
import {
  green, pink, deepOrange, deepPurple,
} from '@material-ui/core/colors';
import graphql from 'babel-plugin-relay/macro';
import { withStyles } from '@material-ui/core/styles';
import Paper from '@material-ui/core/Paper';
import Avatar from '@material-ui/core/Avatar';
import {
  AddOutlined,
  EditOutlined,
  LinkOutlined,
  LinkOffOutlined,
} from '@material-ui/icons';
import inject18n from '../../../../components/i18n';

const styles = (theme) => ({
  container: {
    marginBottom: 20,
  },
  line: {
    backgroundColor: theme.palette.background.navLight,
    content: ' ',
    display: 'block',
    position: 'absolute',
    top: 50,
    left: 20,
    width: 1,
    height: 18,
  },
  avatar: {
    float: 'left',
    width: 40,
    height: 40,
    marginRight: 20,
  },
  content: {
    height: 50,
    width: 'auto',
    overflow: 'hidden',
  },
  paper: {
    width: '100%',
    height: '100%',
    backgroundColor: theme.palette.background.navLight,
    padding: '17px 15px 15px 15px',
  },
  description: {
    whiteSpace: 'nowrap',
    overflow: 'hidden',
    textOverflow: 'ellipsis',
  },
  date: {
    float: 'right',
    textAlign: 'right',
    width: 150,
  },
});

class StixObjectHistoryLineComponent extends Component {
  renderIcon(eventType) {
    switch (eventType) {
      case 'create':
        return (
          <Avatar
            style={{
              marginTop: 5,
              backgroundColor: pink[500],
              color: '#ffffff',
            }}
          >
            <AddOutlined />
          </Avatar>
        );
      case 'add_relation':
        return (
          <Avatar
            style={{
              marginTop: 5,
              backgroundColor: deepOrange[500],
              color: '#ffffff',
            }}
          >
            <LinkOutlined />
          </Avatar>
        );
      case 'remove_relation':
        return (
          <Avatar
            style={{
              marginTop: 5,
              backgroundColor: deepPurple[500],
              color: '#ffffff',
            }}
          >
            <LinkOffOutlined />
          </Avatar>
        );
      default:
        return (
          <Avatar
            style={{
              marginTop: 5,
              backgroundColor: green[500],
              color: '#ffffff',
            }}
          >
            <EditOutlined />
          </Avatar>
        );
    }
  }

  renderDescription(eventType, eventUser, eventData) {
    const { t, classes } = this.props;
    const data = JSON.parse(eventData);
    const userName = eventUser.firstname && eventUser.lastname
      ? `${eventUser.firstname} ${eventUser.lastname}`
      : eventUser.name;

    let fieldName;
    let fieldValue;
    let relationType;
    let name;
    if (eventType === 'update') {
      fieldName = data.key;
      fieldValue = data.value ? join(', ', data.value) : '';
    }
    if (eventType === 'add_relation' || eventType === 'remove_relation') {
      relationType = data.relationship_type;
      if (data.definition) {
        name = data.definition;
      } else if (data.value) {
        name = data.value;
      } else if (data.observable_value) {
        name = data.value;
      } else if (data.indicator_pattern) {
        name = data.indicator_pattern;
      } else {
        name = data.name;
      }
    }
    switch (eventType) {
      case 'create':
        return (
          <div className={classes.description}>
            {' '}
            <code>
              <Link to={`/dashboard/entities/persons/${eventUser.id}`}>
                {userName}
              </Link>
            </code>
            &nbsp;
            {t('has created this entity.')}
          </div>
        );
      case 'add_relation':
        return (
          <div className={classes.description}>
            {' '}
            <code>
              <Link to={`/dashboard/entities/persons/${eventUser.id}`}>
                {userName}
              </Link>
            </code>
            &nbsp;
            {t('has created a relation')}
            &nbsp;
            <code>{t(`relation_${relationType}`)}</code>
            &nbsp;
            {t('to')}
            &nbsp;
            {t(`entity_${data.entity_type}`).toLowerCase()}
            &nbsp;
            <code>{name}</code>
          </div>
        );
      case 'remove_relation':
        return (
          <div className={classes.description}>
            {' '}
            <code>
              <Link to={`/dashboard/entities/persons/${eventUser.id}`}>
                {userName}
              </Link>
            </code>
            &nbsp;
            {t('has removed a relation')}
            &nbsp;
            <code>{t(`relation_${relationType}`)}</code>
            &nbsp;
            {t('to')}
            &nbsp;
            {t(`entity_${data.entity_type}`).toLowerCase()}
            &nbsp;
            <code>{name}</code>
          </div>
        );
      default:
        return (
          <div className={classes.description}>
            <code>
              <Link to={`/dashboard/entities/persons/${eventUser.id}`}>
                {userName}
              </Link>
            </code>
            &nbsp;
            {t('has updated the field')}
            &nbsp;
            <code>{fieldName}</code>
            &nbsp;
            {t('with the value')}
            &nbsp;
            <code>{fieldValue}</code>
          </div>
        );
    }
  }

  render() {
    const { nsdt, classes, node } = this.props;
    return (
      <div className={classes.container}>
        <div className={classes.avatar}>{this.renderIcon(node.event_type)}</div>
        <div className={classes.content}>
          <Paper classes={{ root: classes.paper }}>
            <div className={classes.date}>{nsdt(node.event_date)}</div>
            {this.renderDescription(
              node.event_type,
              node.event_user,
              node.event_data,
            )}
          </Paper>
        </div>
        <div className={classes.line} />
      </div>
    );
  }
}

StixObjectHistoryLineComponent.propTypes = {
  node: PropTypes.object,
  classes: PropTypes.object,
  t: PropTypes.func,
  nsdt: PropTypes.func,
};

const StixObjectHistoryLine = createFragmentContainer(
  StixObjectHistoryLineComponent,
  {
    node: graphql`
      fragment StixObjectHistoryLine_node on Log {
        id
        event_type
        event_date
        event_entity_id
        event_user {
          id
          name
          firstname
          lastname
          user_email
        }
        event_data
      }
    `,
  },
);

export default compose(inject18n, withStyles(styles))(StixObjectHistoryLine);
