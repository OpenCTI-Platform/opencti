import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import { compose } from 'ramda';
import { createFragmentContainer, graphql } from 'react-relay';
import { deepOrange, deepPurple, green, indigo, pink, red, teal, yellow } from '@mui/material/colors';
import withStyles from '@mui/styles/withStyles';
import Paper from '@mui/material/Paper';
import Badge from '@mui/material/Badge';
import Avatar from '@mui/material/Avatar';
import { AddOutlined, DeleteOutlined, EditOutlined, HelpOutlined, LinkOffOutlined, LinkOutlined, OpenInBrowserOutlined } from '@mui/icons-material';
import { LinkVariantPlus, LinkVariantRemove, Merge } from 'mdi-material-ui';
import Tooltip from '@mui/material/Tooltip';
import DialogTitle from '@mui/material/DialogTitle';
import DialogContent from '@mui/material/DialogContent';
import DialogActions from '@mui/material/DialogActions';
import Button from '@mui/material/Button';
import Dialog from '@mui/material/Dialog';
import List from '@mui/material/List';
import ListItemIcon from '@mui/material/ListItemIcon';
import ListItemText from '@mui/material/ListItemText';
import ListItemSecondaryAction from '@mui/material/ListItemSecondaryAction';
import ListItem from '@mui/material/ListItem';
import DialogContentText from '@mui/material/DialogContentText';
import IconButton from '@mui/material/IconButton';
import { Link } from 'react-router-dom';
import withTheme from '@mui/styles/withTheme';
import { truncate } from '../../../../utils/String';
import inject18n from '../../../../components/i18n';
import MarkdownDisplay from '../../../../components/MarkdownDisplay';
import Transition from '../../../../components/Transition';
import ItemIcon from '../../../../components/ItemIcon';

const styles = () => ({
  container: {
    marginBottom: 5,
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
    width: 30,
    height: 30,
    margin: '7px 0 0 0',
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
    padding: '8px 15px 0 15px',
    background: 0,
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
    paddingTop: 4,
    fontSize: 11,
  },
});

class StixCoreObjectHistoryLineComponent extends Component {
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

  renderIcon(eventScope, isRelation, eventMesage, commit) {
    const { theme } = this.props;
    if (isRelation) {
      if (eventScope === 'create') {
        return (
          <Avatar
            sx={{
              width: 25,
              height: 25,
              backgroundColor: 'transparent',
              border: `1px solid ${pink[500]}`,
              color: theme.palette.text.primary,
              cursor: commit ? 'pointer' : 'auto',
            }}
            onClick={() => commit && this.handleOpen()}
          >
            <LinkOutlined style={{ fontSize: 12 }} />
          </Avatar>
        );
      }
      if (eventScope === 'delete') {
        return (
          <Avatar
            sx={{
              width: 25,
              height: 25,
              backgroundColor: 'transparent',
              border: `1px solid ${deepPurple[500]}`,
              color: theme.palette.text.primary,
              cursor: commit ? 'pointer' : 'auto',
            }}
            onClick={() => commit && this.handleOpen()}
          >
            <LinkOffOutlined style={{ fontSize: 12 }} />
          </Avatar>
        );
      }
    } else {
      if (eventScope === 'create') {
        return (
          <Avatar
            sx={{
              width: 25,
              height: 25,
              backgroundColor: 'transparent',
              border: `1px solid ${pink[500]}`,
              color: theme.palette.text.primary,
              cursor: commit ? 'pointer' : 'auto',
            }}
            onClick={() => commit && this.handleOpen()}
          >
            <AddOutlined style={{ fontSize: 12 }} />
          </Avatar>
        );
      }
      if (eventScope === 'merge') {
        return (
          <Avatar
            sx={{
              width: 25,
              height: 25,
              backgroundColor: 'transparent',
              border: `1px solid ${teal[500]}`,
              color: theme.palette.text.primary,
              cursor: commit ? 'pointer' : 'auto',
            }}
            onClick={() => commit && this.handleOpen()}
          >
            <Merge style={{ fontSize: 12 }} />
          </Avatar>
        );
      }
      if (eventScope === 'update' && eventMesage.includes('replaces')) {
        return (
          <Avatar
            sx={{
              width: 25,
              height: 25,
              backgroundColor: 'transparent',
              border: `1px solid ${green[500]}`,
              color: theme.palette.text.primary,
              cursor: commit ? 'pointer' : 'auto',
            }}
            onClick={() => commit && this.handleOpen()}
          >
            <EditOutlined style={{ fontSize: 12 }} />
          </Avatar>
        );
      }
      if (eventScope === 'update' && eventMesage.includes('changes')) {
        return (
          <Avatar
            sx={{
              width: 25,
              height: 25,
              backgroundColor: 'transparent',
              border: `1px solid ${green[500]}`,
              color: theme.palette.text.primary,
              cursor: commit ? 'pointer' : 'auto',
            }}
            onClick={() => commit && this.handleOpen()}
          >
            <EditOutlined style={{ fontSize: 12 }} />
          </Avatar>
        );
      }
      if (eventScope === 'update' && eventMesage.includes('adds')) {
        return (
          <Avatar
            sx={{
              width: 25,
              height: 25,
              backgroundColor: 'transparent',
              border: `1px solid ${indigo[500]}`,
              color: theme.palette.text.primary,
              cursor: commit ? 'pointer' : 'auto',
            }}
            onClick={() => commit && this.handleOpen()}
          >
            <LinkVariantPlus style={{ fontSize: 12 }} />
          </Avatar>
        );
      }
      if (eventScope === 'update' && eventMesage.includes('removes')) {
        return (
          <Avatar
            sx={{
              width: 25,
              height: 25,
              backgroundColor: 'transparent',
              border: `1px solid ${deepOrange[500]}`,
              color: theme.palette.text.primary,
              cursor: commit ? 'pointer' : 'auto',
            }}
            onClick={() => commit && this.handleOpen()}
          >
            <LinkVariantRemove style={{ fontSize: 12 }} />
          </Avatar>
        );
      }
      if (eventScope === 'delete') {
        return (
          <Avatar
            sx={{
              width: 25,
              height: 25,
              backgroundColor: 'transparent',
              border: `1px solid ${red[500]}`,
              color: theme.palette.text.primary,
            }}
          >
            <DeleteOutlined style={{ fontSize: 12 }} />
          </Avatar>
        );
      }
    }
    return (
      <Avatar
        style={{
          width: 25,
          height: 25,
          backgroundColor: 'transparent',
          border: `1px solid ${yellow[500]}`,
          color: theme.palette.text.primary,
          cursor: commit ? 'pointer' : 'auto',
        }}
        onClick={() => commit && this.handleOpen()}
      >
        <HelpOutlined style={{ fontSize: 12 }} />
      </Avatar>
    );
  }

  render() {
    const { nsdt, classes, node, isRelation, t } = this.props;
    return (
      <div className={classes.container}>
        <div className={classes.avatar}>
          <Badge
            color="secondary"
            overlap="circular"
            badgeContent="M"
            invisible={node.context_data.commit === null}
          >
            {this.renderIcon(
              node.event_scope,
              isRelation,
              node.context_data.message,
              node.context_data.commit,
            )}
          </Badge>
        </div>
        <div
          className={classes.content}
          style={{
            height:
              node.context_data.external_references
              && node.context_data.external_references.length > 0
                ? 'auto'
                : 40,
          }}
        >
          <Paper classes={{ root: classes.paper }}>
            <div className={classes.date}>{nsdt(node.timestamp)}</div>
            <Tooltip
              classes={{ tooltip: classes.tooltip }}
              title={
                <MarkdownDisplay
                  content={`\`${node.user.name}\` ${node.context_data.message}`}
                  remarkGfmPlugin={true}
                  commonmark={true}
                />
              }
            >
              <div className={classes.description}>
                <MarkdownDisplay
                  content={`\`${node.user.name}\` ${node.context_data.message}`}
                  remarkGfmPlugin={true}
                  commonmark={true}
                />
              </div>
            </Tooltip>
            {node.context_data.external_references
              && node.context_data.external_references.length > 0 && (
                <List>
                  {node.context_data.external_references.map(
                    (externalReference) => {
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
                            component={Link}
                            key={externalReference.id}
                            to={`/dashboard/analyses/external_references/${externalReference.id}`}
                            dense={true}
                            divider={true}
                            button={true}
                          >
                            <ListItemIcon>
                              <ItemIcon type="External-Reference" />
                            </ListItemIcon>
                            <ListItemText
                              primary={`${externalReference.source_name} ${externalReferenceId}`}
                              secondary={truncate(
                                externalReferenceSecondary,
                                90,
                              )}
                            />
                            <ListItemSecondaryAction>
                              <Tooltip title={t('Browse the link')}>
                                <IconButton
                                  onClick={this.handleOpenExternalLink.bind(
                                    this,
                                    externalReference.url,
                                  )}
                                  size="large"
                                  color="primary"
                                >
                                  <OpenInBrowserOutlined />
                                </IconButton>
                              </Tooltip>
                            </ListItemSecondaryAction>
                          </ListItem>
                        );
                      }
                      return (
                        <ListItem
                          component={Link}
                          key={externalReference.id}
                          to={`/dashboard/analyses/external_references/${externalReference.id}`}
                          dense={true}
                          divider={true}
                          button={true}
                        >
                          <ListItemIcon>
                            <ItemIcon type="External-Reference" />
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
                    },
                  )}
                </List>
            )}
          </Paper>
        </div>
        <div className={classes.line} />
        <Dialog
          PaperProps={{ elevation: 1 }}
          open={this.state.open}
          onClose={this.handleClose.bind(this)}
          fullWidth={true}
        >
          <DialogTitle>{t('Commit message')}</DialogTitle>
          <DialogContent>
            <MarkdownDisplay
              content={node.context_data.commit}
              remarkGfmPlugin={true}
              commonmark={true}
            />
          </DialogContent>
          <DialogActions>
            <Button color="primary" onClick={this.handleClose.bind(this)}>
              {t('Close')}
            </Button>
          </DialogActions>
        </Dialog>
        <Dialog
          PaperProps={{ elevation: 1 }}
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
        event_scope
        timestamp
        user {
          name
        }
        context_data {
          message
          commit
          external_references {
            id
            source_name
            external_id
            url
            description
          }
        }
      }
    `,
  },
);

export default compose(
  inject18n,
  withTheme,
  withStyles(styles),
)(StixCoreObjectHistoryLine);
