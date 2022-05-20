import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import Markdown from 'react-markdown';
import { compose } from 'ramda';
import { graphql, createFragmentContainer } from 'react-relay';
import {
  green,
  pink,
  deepOrange,
  deepPurple,
  yellow,
  indigo,
  teal,
  red,
} from '@mui/material/colors';
import withStyles from '@mui/styles/withStyles';
import Paper from '@mui/material/Paper';
import Badge from '@mui/material/Badge';
import Avatar from '@mui/material/Avatar';
import {
  AddOutlined,
  EditOutlined,
  LinkOutlined,
  LinkOffOutlined,
  HelpOutlined,
  LanguageOutlined,
  DeleteOutlined,
} from '@mui/icons-material';
import { LinkVariantPlus, LinkVariantRemove, Merge } from 'mdi-material-ui';
import Tooltip from '@mui/material/Tooltip';
import DialogTitle from '@mui/material/DialogTitle';
import DialogContent from '@mui/material/DialogContent';
import DialogActions from '@mui/material/DialogActions';
import Button from '@mui/material/Button';
import Dialog from '@mui/material/Dialog';
import remarkGfm from 'remark-gfm';
import remarkParse from 'remark-parse';
import List from '@mui/material/List';
import ListItemIcon from '@mui/material/ListItemIcon';
import ListItemText from '@mui/material/ListItemText';
import ListItem from '@mui/material/ListItem';
import DialogContentText from '@mui/material/DialogContentText';
import Slide from '@mui/material/Slide';
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
    height: 18,
  },
  avatar: {
    float: 'left',
    width: 40,
    height: 40,
    margin: '5px 10px 0 0',
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
    backgroundColor: theme.palette.background.shadow,
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

  renderIcon(eventType, isRelation, eventMesage, commit) {
    if (isRelation) {
      if (eventType === 'create') {
        return (
          <Avatar
            sx={{
              width: 30,
              height: 30,
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
            sx={{
              width: 30,
              height: 30,
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
            sx={{
              width: 30,
              height: 30,
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
            sx={{
              width: 30,
              height: 30,
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
            sx={{
              width: 30,
              height: 30,
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
            sx={{
              width: 30,
              height: 30,
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
            sx={{
              width: 30,
              height: 30,
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
            sx={{
              width: 30,
              height: 30,
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
      if (eventType === 'delete') {
        return (
          <Avatar
            sx={{
              width: 30,
              height: 30,
              backgroundColor: red[500],
              color: '#ffffff',
            }}
          >
            <DeleteOutlined fontSize="small" />
          </Avatar>
        );
      }
    }
    return (
      <Avatar
        style={{
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
              node.event_type,
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
              node.context_data.references
              && node.context_data.references.length > 0
                ? 'auto'
                : 40,
          }}
        >
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
          PaperProps={{ elevation: 1 }}
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
)(StixCoreObjectHistoryLine);
