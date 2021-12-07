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
import Avatar from '@material-ui/core/Avatar';
import {
  AddOutlined,
  EditOutlined,
  LinkOutlined,
  LinkOffOutlined,
  HelpOutlined,
  LanguageOutlined,
} from '@material-ui/icons';
import { LinkVariantPlus, LinkVariantRemove, Merge } from 'mdi-material-ui';
import Tooltip from '@material-ui/core/Tooltip/Tooltip';
import remarkGfm from 'remark-gfm';
import remarkParse from 'remark-parse';
import List from '@material-ui/core/List';
import ListItem from '@material-ui/core/ListItem';
import ListItemIcon from '@material-ui/core/ListItemIcon';
import ListItemText from '@material-ui/core/ListItemText';
import Badge from '@material-ui/core/Badge';
import Dialog from '@material-ui/core/Dialog';
import DialogTitle from '@material-ui/core/DialogTitle';
import DialogContent from '@material-ui/core/DialogContent';
import DialogActions from '@material-ui/core/DialogActions';
import Button from '@material-ui/core/Button';
import DialogContentText from '@material-ui/core/DialogContentText';
import Slide from '@material-ui/core/Slide';
import { truncate } from '../../../../utils/String';
import inject18n from '../../../../components/i18n';

const Transition = React.forwardRef((props, ref) => (
  <Slide direction="up" ref={ref} {...props} />
));
Transition.displayName = 'TransitionSlide';

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
  },
  avatar: {
    float: 'left',
    width: 40,
    height: 40,
    marginRight: 20,
  },
  avatarReference: {
    width: 24,
    height: 24,
    backgroundColor: theme.palette.primary.main,
  },
  content: {
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
    padding: 15,
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

class StixCoreRelationshipHistoryLineComponent extends Component {
  constructor(props) {
    super(props);
    this.state = {
      open: false,
      displayExternalLink: false,
      externalLink: null,
    };
  }

  handleOpen() {
    this.setState({ open: true });
  }

  handleClose() {
    this.setState({ open: false });
  }

  handleOpenExternalLink(url) {
    this.setState({ displayExternalLink: true, externalLink: url });
  }

  handleCloseExternalLink() {
    this.setState({ displayExternalLink: false, externalLink: null });
  }

  handleBrowseExternalLink() {
    window.open(this.state.externalLink, '_blank');
    this.setState({ displayExternalLink: false, externalLink: null });
  }

  // eslint-disable-next-line class-methods-use-this
  renderIcon(eventType, isRelation, eventMesage, commit) {
    if (isRelation) {
      if (eventType === 'create') {
        return (
          <Avatar
            style={{
              marginTop: 2,
              backgroundColor: pink[500],
              color: '#ffffff',
              cursor: commit ? 'pointer' : 'auto',
            }}
            onClick={() => commit && this.handleOpen()}
          >
            <LinkOutlined fontSize="small" />
          </Avatar>
        );
      }
      if (eventType === 'delete') {
        return (
          <Avatar
            style={{
              marginTop: 2,
              backgroundColor: deepPurple[500],
              color: '#ffffff',
              cursor: commit ? 'pointer' : 'auto',
            }}
            onClick={() => commit && this.handleOpen()}
          >
            <LinkOffOutlined fontSize="small" />
          </Avatar>
        );
      }
    } else {
      if (eventType === 'create') {
        return (
          <Avatar
            style={{
              marginTop: 2,
              backgroundColor: pink[500],
              color: '#ffffff',
              cursor: commit ? 'pointer' : 'auto',
            }}
            onClick={() => commit && this.handleOpen()}
          >
            <AddOutlined fontSize="small" />
          </Avatar>
        );
      }
      if (eventType === 'merge') {
        return (
          <Avatar
            style={{
              marginTop: 2,
              backgroundColor: teal[500],
              color: '#ffffff',
              cursor: commit ? 'pointer' : 'auto',
            }}
            onClick={() => commit && this.handleOpen()}
          >
            <Merge fontSize="small" />
          </Avatar>
        );
      }
      if (eventType === 'update' && eventMesage.includes('replaces')) {
        return (
          <Avatar
            style={{
              marginTop: 2,
              backgroundColor: green[500],
              color: '#ffffff',
              cursor: commit ? 'pointer' : 'auto',
            }}
            onClick={() => commit && this.handleOpen()}
          >
            <EditOutlined fontSize="small" />
          </Avatar>
        );
      }
      if (eventType === 'update' && eventMesage.includes('changes')) {
        return (
          <Avatar
            style={{
              marginTop: 2,
              backgroundColor: green[500],
              color: '#ffffff',
              cursor: commit ? 'pointer' : 'auto',
            }}
            onClick={() => commit && this.handleOpen()}
          >
            <EditOutlined fontSize="small" />
          </Avatar>
        );
      }
      if (eventType === 'update' && eventMesage.includes('adds')) {
        return (
          <Avatar
            style={{
              marginTop: 2,
              backgroundColor: indigo[500],
              color: '#ffffff',
              cursor: commit ? 'pointer' : 'auto',
            }}
            onClick={() => commit && this.handleOpen()}
          >
            <LinkVariantPlus fontSize="small" />
          </Avatar>
        );
      }
      if (eventType === 'update' && eventMesage.includes('removes')) {
        return (
          <Avatar
            style={{
              marginTop: 2,
              backgroundColor: deepOrange[500],
              color: '#ffffff',
              cursor: commit ? 'pointer' : 'auto',
            }}
            onClick={() => commit && this.handleOpen()}
          >
            <LinkVariantRemove fontSize="small" />
          </Avatar>
        );
      }
    }
    return (
      <Avatar
        style={{
          marginTop: 2,
          backgroundColor: yellow[800],
          color: '#ffffff',
          cursor: commit ? 'pointer' : 'auto',
        }}
        onClick={() => commit && this.handleOpen()}
      >
        <HelpOutlined fontSize="small" />
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
            {node.context_data.references
              && node.context_data.references.length > 0 && (
                <List>
                  {node.context_data.references.map((externalReference) => {
                    const externalReferenceId = externalReference.external_id
                      ? `(${externalReference.external_id})`
                      : '';
                    let externalReferenceSecondary = '';
                    if (
                      externalReference.url
                      && externalReference.url.length > 0
                    ) {
                      externalReferenceSecondary = externalReference.url;
                    } else if (
                      externalReference.description
                      && externalReference.description.length > 0
                    ) {
                      externalReferenceSecondary = externalReference.description;
                    }
                    if (externalReference.url) {
                      return (
                        <ListItem
                          key={externalReference.id}
                          dense={true}
                          divider={true}
                          button={true}
                          onClick={this.handleOpenExternalLink.bind(
                            this,
                            externalReference.url,
                          )}
                        >
                          <ListItemIcon>
                            <LanguageOutlined />
                          </ListItemIcon>
                          <ListItemText
                            primary={`${externalReference.source_name} ${externalReferenceId}`}
                            secondary={truncate(externalReferenceSecondary, 90)}
                          />
                        </ListItem>
                      );
                    }
                    return (
                      <ListItem
                        key={externalReference.id}
                        dense={true}
                        divider={true}
                        button={false}
                      >
                        <ListItemIcon>
                          <Avatar classes={{ root: classes.avatar }}>
                            {externalReference.source_name.substring(0, 1)}
                          </Avatar>
                        </ListItemIcon>
                        <ListItemText
                          primary={`${externalReference.source_name} ${externalReferenceId}`}
                          secondary={truncate(
                            externalReference.description,
                            120,
                          )}
                        />
                      </ListItem>
                    );
                  })}
                </List>
            )}
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
        <Dialog
          open={this.state.displayExternalLink}
          keepMounted={true}
          TransitionComponent={Transition}
          onClose={this.handleCloseExternalLink.bind(this)}
        >
          <DialogContent>
            <DialogContentText>
              {t('Do you want to browse this external link?')}
            </DialogContentText>
          </DialogContent>
          <DialogActions>
            <Button onClick={this.handleCloseExternalLink.bind(this)}>
              {t('Cancel')}
            </Button>
            <Button
              button={true}
              color="secondary"
              onClick={this.handleBrowseExternalLink.bind(this)}
            >
              {t('Browse the link')}
            </Button>
          </DialogActions>
        </Dialog>
      </div>
    );
  }
}

StixCoreRelationshipHistoryLineComponent.propTypes = {
  node: PropTypes.object,
  classes: PropTypes.object,
  t: PropTypes.func,
  nsdt: PropTypes.func,
  isRelation: PropTypes.bool,
};

const StixCoreRelationshipHistoryLine = createFragmentContainer(
  StixCoreRelationshipHistoryLineComponent,
  {
    node: graphql`
      fragment StixCoreRelationshipHistoryLine_node on Log {
        id
        event_type
        timestamp
        user {
          name
        }
        context_data {
          message
          commit
          references {
            id
            source_name
            external_id
            url
            created
            description
          }
        }
      }
    `,
  },
);

export default compose(
  inject18n,
  withStyles(styles),
)(StixCoreRelationshipHistoryLine);
