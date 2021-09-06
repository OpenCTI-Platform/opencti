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
  teal,
} from '@material-ui/core/colors';
import graphql from 'babel-plugin-relay/macro';
import { withStyles } from '@material-ui/core/styles';
import Paper from '@material-ui/core/Paper';
import Badge from '@material-ui/core/Badge';
import Avatar from '@material-ui/core/Avatar';
import {
  AddOutlined,
  EditOutlined,
  LinkOutlined,
  LinkOffOutlined,
  HelpOutlined,
} from '@material-ui/icons';
import { LinkVariantPlus, LinkVariantRemove, Merge } from 'mdi-material-ui';
import Tooltip from '@material-ui/core/Tooltip/Tooltip';
import DialogTitle from '@material-ui/core/DialogTitle';
import DialogContent from '@material-ui/core/DialogContent';
import DialogActions from '@material-ui/core/DialogActions';
import Button from '@material-ui/core/Button';
import Dialog from '@material-ui/core/Dialog';
import remarkGfm from 'remark-gfm';
import remarkParse from 'remark-parse';
import inject18n from '../../../../components/i18n';

const styles = (theme) => ({
  container: {
    marginBottom: 20,
  },
  line: {
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
  },
  paper: {
    width: '100%',
    height: '100%',
    backgroundColor: theme.palette.background.line,
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
    width: 180,
  },
});

class StixCoreObjectHistoryLineComponent extends Component {
  constructor(props) {
    super(props);
    this.state = { open: false };
  }

  handleOpen() {
    this.setState({ open: true });
  }

  handleClose() {
    this.setState({ open: false });
  }

  renderIcon(eventType, isRelation, eventMesage, commit) {
    if (isRelation) {
      if (eventType === 'create') {
        return (
          <Avatar
            style={{
              marginTop: 5,
              backgroundColor: pink[500],
              color: '#ffffff',
              cursor: commit ? 'pointer' : 'auto',
            }}
            onClick={() => commit && this.handleOpen()}
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
              cursor: commit ? 'pointer' : 'auto',
            }}
            onClick={() => commit && this.handleOpen()}
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
              cursor: commit ? 'pointer' : 'auto',
            }}
            onClick={() => commit && this.handleOpen()}
          >
            <AddOutlined />
          </Avatar>
        );
      }
      if (eventType === 'merge') {
        return (
          <Avatar
            style={{
              marginTop: 5,
              backgroundColor: teal[500],
              color: '#ffffff',
              cursor: commit ? 'pointer' : 'auto',
            }}
            onClick={() => commit && this.handleOpen()}
          >
            <Merge />
          </Avatar>
        );
      }
      if (eventType === 'update' && eventMesage.includes('replaces')) {
        return (
          <Avatar
            style={{
              marginTop: 5,
              backgroundColor: green[500],
              color: '#ffffff',
              cursor: commit ? 'pointer' : 'auto',
            }}
            onClick={() => commit && this.handleOpen()}
          >
            <EditOutlined />
          </Avatar>
        );
      }
      if (eventType === 'update' && eventMesage.includes('changes')) {
        return (
          <Avatar
            style={{
              marginTop: 5,
              backgroundColor: green[500],
              color: '#ffffff',
              cursor: commit ? 'pointer' : 'auto',
            }}
            onClick={() => commit && this.handleOpen()}
          >
            <EditOutlined />
          </Avatar>
        );
      }
      if (eventType === 'update' && eventMesage.includes('adds')) {
        return (
          <Avatar
            style={{
              marginTop: 5,
              backgroundColor: indigo[500],
              color: '#ffffff',
              cursor: commit ? 'pointer' : 'auto',
            }}
            onClick={() => commit && this.handleOpen()}
          >
            <LinkVariantPlus />
          </Avatar>
        );
      }
      if (eventType === 'update' && eventMesage.includes('removes')) {
        return (
          <Avatar
            style={{
              marginTop: 5,
              backgroundColor: deepOrange[500],
              color: '#ffffff',
              cursor: commit ? 'pointer' : 'auto',
            }}
            onClick={() => commit && this.handleOpen()}
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
          backgroundColor: yellow[800],
          color: '#ffffff',
          cursor: commit ? 'pointer' : 'auto',
        }}
        onClick={() => commit && this.handleOpen()}
      >
        <HelpOutlined />
      </Avatar>
    );
  }

  render() {
    const {
      nsdt, classes, node, isRelation, t,
    } = this.props;
    return (
      <div className={classes.container}>
        <div className={classes.avatar}>
          <Badge
            color="secondary"
            overlap="circle"
            badgeContent="M"
            invisible={node.context_data.commit === null}
          >
            {this.renderIcon(
              node.event_type,
              isRelation,
              node.context_data.message,
              node.context_data.commit,
            )}
          </Badge>
        </div>
        <div className={classes.content}>
          <Paper classes={{ root: classes.paper }}>
            <div className={classes.date}>{nsdt(node.timestamp)}</div>
            <Tooltip
              classes={{ tooltip: classes.tooltip }}
              title={
                <Markdown
                  remarkPlugins={[remarkGfm, remarkParse]}
                  parserOptions={{ commonmark: true }}
                  className="markdown"
                >
                  {`\`${node.user.name}\` ${node.context_data.message}`}
                </Markdown>
              }
            >
              <div className={classes.description}>
                <Markdown
                  remarkPlugins={[remarkGfm, remarkParse]}
                  parserOptions={{ commonmark: true }}
                  className="markdown"
                >
                  {`\`${node.user.name}\` ${node.context_data.message}`}
                </Markdown>
              </div>
            </Tooltip>
          </Paper>
        </div>
        <div className={classes.line} />
        <Dialog
          open={this.state.open}
          onClose={this.handleClose.bind(this)}
          fullWidth={true}
        >
          <DialogTitle>{t('Commit message')}</DialogTitle>
          <DialogContent>
            <Markdown
              remarkPlugins={[remarkGfm, remarkParse]}
              parserOptions={{ commonmark: true }}
              className="markdown"
            >
              {node.context_data.commit}
            </Markdown>
          </DialogContent>
          <DialogActions>
            <Button color="primary" onClick={this.handleClose.bind(this)}>
              {t('Close')}
            </Button>
          </DialogActions>
        </Dialog>
      </div>
    );
  }
}

StixCoreObjectHistoryLineComponent.propTypes = {
  node: PropTypes.object,
  classes: PropTypes.object,
  t: PropTypes.func,
  nsdt: PropTypes.func,
  isRelation: PropTypes.bool,
};

const StixCoreObjectHistoryLine = createFragmentContainer(
  StixCoreObjectHistoryLineComponent,
  {
    node: graphql`
      fragment StixCoreObjectHistoryLine_node on Log {
        id
        event_type
        timestamp
        user {
          name
        }
        context_data {
          message
          commit
        }
      }
    `,
  },
);

export default compose(
  inject18n,
  withStyles(styles),
)(StixCoreObjectHistoryLine);
