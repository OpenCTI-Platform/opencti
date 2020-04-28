import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import Markdown from 'react-markdown';
import { compose } from 'ramda';
import { createFragmentContainer } from 'react-relay';
import {
  green,
  pink,
  deepOrange,
  deepPurple,
  yellow,
  indigo,
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
  HelpOutlined,
} from '@material-ui/icons';
import { LinkVariantPlus, LinkVariantRemove } from 'mdi-material-ui';
import Tooltip from '@material-ui/core/Tooltip/Tooltip';
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
  tooltip: {
    maxWidth: '80%',
    lineHeight: 2,
    padding: 10,
    backgroundColor: '#323232',
  },
  paper: {
    width: '100%',
    height: '100%',
    backgroundColor: theme.palette.background.navLight,
    padding: '17px 15px 15px 15px',
  },
  description: {
    height: '100%',
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
  renderIcon(eventType, isRelation) {
    if (isRelation) {
      if (eventType === 'create') {
        return (
          <Avatar
            style={{
              marginTop: 5,
              backgroundColor: pink[500],
              color: '#ffffff',
            }}
          >
            <LinkOutlined />
          </Avatar>
        );
      }
      if (eventType === 'delete') {
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
      }
    } else {
      if (eventType === 'create') {
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
      }
      if (eventType === 'update') {
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
      if (eventType === 'update_add') {
        return (
          <Avatar
            style={{
              marginTop: 5,
              backgroundColor: indigo[500],
              color: '#ffffff',
            }}
          >
            <LinkVariantPlus />
          </Avatar>
        );
      }
      if (eventType === 'update_remove') {
        return (
          <Avatar
            style={{
              marginTop: 5,
              backgroundColor: deepOrange[500],
              color: '#ffffff',
            }}
          >
            <LinkVariantRemove />
          </Avatar>
        );
      }
    }
    return (
      <Avatar
        style={{
          marginTop: 5,
          backgroundColor: yellow[500],
          color: '#ffffff',
        }}
      >
        <HelpOutlined />
      </Avatar>
    );
  }

  render() {
    const {
      nsdt, classes, node, isRelation,
    } = this.props;
    return (
      <div className={classes.container}>
        <div className={classes.avatar}>
          {this.renderIcon(node.event_type, isRelation)}
        </div>
        <div className={classes.content}>
          <Paper classes={{ root: classes.paper }}>
            <div className={classes.date}>{nsdt(node.event_date)}</div>
            <Tooltip
              classes={{ tooltip: classes.tooltip }}
              title={
                <Markdown
                  className="markdown"
                  source={`\`${node.event_user.name}\` ${node.event_message}`}
                />
              }
            >
              <div className={classes.description}>
                <Markdown
                  className="markdown"
                  source={`\`${node.event_user.name}\` ${node.event_message}`}
                />
              </div>
            </Tooltip>
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
  isRelation: PropTypes.bool,
};

const StixObjectHistoryLine = createFragmentContainer(
  StixObjectHistoryLineComponent,
  {
    node: graphql`
      fragment StixObjectHistoryLine_node on Log {
        id
        event_type
        event_date
        event_user {
          name
        }
        event_message
        event_data
      }
    `,
  },
);

export default compose(inject18n, withStyles(styles))(StixObjectHistoryLine);
