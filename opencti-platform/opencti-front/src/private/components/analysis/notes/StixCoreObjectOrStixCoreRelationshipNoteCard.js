import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import { compose, pathOr, take } from 'ramda';
// import { createFragmentContainer } from 'react-relay';
import { Link } from 'react-router-dom';
import Markdown from 'react-markdown';
import graphql from 'babel-plugin-relay/macro';
import { OpenInNewOutlined, ExpandMoreOutlined, ExpandLessOutlined } from '@material-ui/icons';
import { withStyles, withTheme } from '@material-ui/core/styles';
import Card from '@material-ui/core/Card';
import Collapse from '@material-ui/core/Collapse';
import CardContent from '@material-ui/core/CardContent';
import CardHeader from '@material-ui/core/CardHeader';
import Divider from '@material-ui/core/Divider';
import CardActions from '@material-ui/core/CardActions';
import Typography from '@material-ui/core/Typography';
import LinkIcon from '@material-ui/icons/Link';
import { ConnectionHandler } from 'relay-runtime';
import Dialog from '@material-ui/core/Dialog';
import DialogContent from '@material-ui/core/DialogContent';
import DialogContentText from '@material-ui/core/DialogContentText';
import DialogActions from '@material-ui/core/DialogActions';
import Button from '@material-ui/core/Button';
import Slide from '@material-ui/core/Slide';
import IconButton from '@material-ui/core/IconButton';
import remarkGfm from 'remark-gfm';
import remarkParse from 'remark-parse';
import { QueryRenderer as QR, commitMutation as CM, createFragmentContainer } from 'react-relay';
import environmentDarkLight from '../../../../relay/environmentDarkLight';
import inject18n from '../../../../components/i18n';
import ItemMarking from '../../../../components/ItemMarking';
import StixCoreObjectLabels from '../../common/stix_core_objects/StixCoreObjectLabels';
import { commitMutation } from '../../../../relay/environment';
import { noteMutationRelationDelete } from './AddNotesLines';
import NotePopover from './NotePopover';
import { resolveLink } from '../../../../utils/Entity';

const styles = (theme) => ({
  card: {
    width: '100%',
    height: '100%',
    borderRadius: 0,
    padding: '24px 24px 12px 24px',
    position: 'relative',
  },
  avatar: {
    backgroundColor: theme.palette.primary.main,
  },
  avatarDisabled: {
    backgroundColor: theme.palette.grey[600],
  },
  icon: {
    margin: '10px 20px 0 0',
    fontSize: 40,
    color: '#242d30',
  },
  area: {
    width: '100%',
    height: '100%',
  },
  description: {
    height: 70,
    overflow: 'hidden',
  },
  objectLabel: {
    height: 45,
    paddingTop: 7,
  },
  external: {
    position: 'absolute',
    bottom: 0,
    right: 0,
    color: theme.palette.text.secondary,
  },
});

const Transition = React.forwardRef((props, ref) => (
  <Slide direction="up" ref={ref} {...props} />
));
Transition.displayName = 'TransitionSlide';

class StixCoreObjectOrStixCoreRelationshipNoteCardComponent extends Component {
  constructor(props) {
    super(props);
    this.state = {
      displayDialog: false,
      noteIdToRemove: null,
      removing: false,
      open: false,
    };
  }

  handleOpenDialog(noteId) {
    this.setState({
      displayDialog: true,
      noteIdToRemove: noteId,
    });
  }

  handleCloseDialog() {
    this.setState({
      displayDialog: false,
      removing: false,
      noteIdToRemove: null,
    });
  }

  toggleExpand() {
    this.setState({
      open: !this.state.open,
    });
  }

  handleRemoval() {
    this.setState({ removing: true });
    this.removeNote(this.state.noteIdToRemove);
  }

  removeNote(noteId) {
    CM(environmentDarkLight, {
      mutation: noteMutationRelationDelete,
      variables: {
        id: noteId,
        toId: this.props.stixCoreObjectOrStixCoreRelationshipId,
        relationship_type: 'object',
      },
      onCompleted: (response) => {
        this.setState({ removing: false });
        this.handleCloseDialog();
        console.log('NoteRemoveDarkLightMutationresponse', response);
      },
      onError: (err) => console.log('NoteRemoveDarkLightMutationError', err),
    });
    // commitMutation({
    //   mutation: noteMutationRelationDelete,
    //   variables: {
    //     id: noteId,
    //     toId: this.props.stixCoreObjectOrStixCoreRelationshipId,
    //     relationship_type: 'object',
    //   },
    //   updater: (store) => {
    //     const entity = store.get(
    //       this.props.stixCoreObjectOrStixCoreRelationshipId,
    //     );
    //     const conn = ConnectionHandler.getConnection(
    //       entity,
    //       'Pagination_notes',
    //     );
    //     ConnectionHandler.deleteNode(conn, noteId);
    //   },
    //   onCompleted: () => {
    //     this.setState({ removing: false });
    //     this.handleCloseDialog();
    //   },
    // });
  }

  render() {
    const {
      nsdt,
      classes,
      node,
      t,
      theme,
      stixCoreObjectOrStixCoreRelationshipId,
    } = this.props;
    let authorName = null;
    let authorLink = null;
    if (node.createdBy) {
      authorName = node.createdBy.name;
      authorLink = `${resolveLink(node.createdBy.entity_type)}/${node.createdBy.id
      }`;
    }
    return (
      <Card classes={{ root: classes.card }} raised={false}>
        <CardHeader
          style={{
            padding: '0px 10px 0 15px',
            // borderBottom: `1px solid ${theme.palette.divider}`,
          }}
          action={
            <NotePopover
              id={node.id}
              entityId={stixCoreObjectOrStixCoreRelationshipId}
              handleOpenRemove={this.handleOpenDialog.bind(this)}
            />
          }
          title={
            <div style={{ display: 'flex', justifyContent: 'space-between' }}>
              <div>
                  <div
                    style={{
                      fontDecoration: 'none',
                      textTransform: 'none',
                      paddingTop: '3px',
                    }}
                  >
                    <strong>
                      {authorLink ? (
                        <Link to={authorLink}>{authorName}</Link>
                      ) : (
                        t('Unknown')
                      )}
                    </strong>
                    <span style={{ color: theme.palette.text.secondary }}>
                      {t(' added a note on ')}
                    </span>
                    {nsdt(node.created)}
                  </div>
                  {/* <div
                    style={{
                      float: 'left',
                      marginLeft: 20,
                      fontDecoration: 'none',
                      textTransform: 'none',
                    }}
                  >
                    {take(1, pathOr([], ['objectMarking', 'edges'], node)).map(
                      (markingDefinition) => (
                        <ItemMarking
                          key={markingDefinition.node.id}
                          label={markingDefinition.node.definition}
                          color={markingDefinition.node.x_opencti_color}
                          variant="inList"
                        />
                      ),
                    )}
                  </div> */}
                  <div
                    style={{
                      float: 'right',
                      fontDecoration: 'none',
                      textTransform: 'none',
                    }}
                  >
                  </div>
              </div>
                <IconButton
                aria-haspopup="true"
                style={{ marginTop: '-6px' }}
                onClick={this.toggleExpand.bind(this)}
                >
                  {this.state.open ? (
                    <ExpandLessOutlined />
                  ) : (
                    <ExpandMoreOutlined />
                  )}
                </IconButton>
              {/* <IconButton
                aria-haspopup="true"
                style={{ marginTop: 1 }}
              >
              {open ? (
                <ExpandLessOutlined
                classes={{ root: classes.toggleButton }}
                onClick={() => this.toggleExpand()} />
              ) : (
                <ExpandLessOutlined
                classes={{ root: classes.toggleButton }}
                onClick={() => this.toggleExpand()} />
              )}
              </IconButton> */}
            </div>
          }
        />
           <CardContent style={{
             padding: '0 0 0 15px',
             // borderBottom: `1px solid ${theme.palette.divider}`,
           }}>
           {
             this.state.open
               ? (
                <Typography style={{ margin: '0 0 10px 0' }} align="left" variant="body2">
                    {node.content}
                </Typography>
               )
               : (
              <Typography
                  variant="body2"
                  noWrap={true}
                  style={{ margin: '0 0 10px 0', fontWeight: 500 }}
                >
                  <Markdown
                    remarkPlugins={[remarkGfm, remarkParse]}
                    parserOptions={{ commonmark: true }}
                    className="markdown"
                  >
                    {node.attribute_abstract}
                  </Markdown>
                </Typography>
               )
           }
                {/* <Markdown
                  remarkPlugins={[remarkGfm, remarkParse]}
                  parserOptions={{ commonmark: true }}
                  className="markdown"
                >
                  {node.content}
                </Markdown> */}
                {/* <IconButton
                  component={Link}
                  to={`/dashboard/analysis/notes/${node.id}`}
                  classes={{ root: classes.external }}
                >
                  <OpenInNewOutlined fontSize="small" />
                </IconButton> */}
            </CardContent>
            <Collapse sx={{ width: '1100px', borderRadius: 0 }} in={this.state.open} timeout="auto" unmountOnExit>
                <CardActions style={{ color: '#F9B406', padding: '0 20px 20px 15px' }}>
                         <StixCoreObjectLabels
                      variant="inList"
                      labels={node.objectLabel}
                    />
                </CardActions>
            </Collapse>
        <Dialog
          open={this.state.displayDialog}
          keepMounted={true}
          TransitionComponent={Transition}
          onClose={this.handleCloseDialog.bind(this)}
        >
          <DialogContent>
            <DialogContentText>
              {t('Do you want to remove this note?')}
            </DialogContentText>
          </DialogContent>
          <DialogActions>
            <Button
              onClick={this.handleCloseDialog.bind(this)}
              disabled={this.state.removing}
            >
              {t('Cancel')}
            </Button>
            <Button
              onClick={this.handleRemoval.bind(this)}
              color="primary"
              disabled={this.state.removing}
            >
              {t('Delete')}
            </Button>
          </DialogActions>
        </Dialog>
        <Divider light={true} />
      </Card>
    );
  }
}

StixCoreObjectOrStixCoreRelationshipNoteCardComponent.propTypes = {
  stixCoreObjectOrStixCoreRelationshipId: PropTypes.string,
  node: PropTypes.object,
  classes: PropTypes.object,
  t: PropTypes.func,
  nsdt: PropTypes.func,
};

const StixCoreObjectOrStixCoreRelationshipNoteCard = createFragmentContainer(
  StixCoreObjectOrStixCoreRelationshipNoteCardComponent,
  {
    node: graphql`
      fragment StixCoreObjectOrStixCoreRelationshipNoteCard_node on Note {
        id
        attribute_abstract
        content
        created
        modified
        createdBy {
          ... on Identity {
            id
            name
            entity_type
          }
        }
        objectMarking {
          edges {
            node {
              id
              definition
              x_opencti_color
            }
          }
        }
        objectLabel {
          edges {
            node {
              id
              value
              color
            }
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
)(StixCoreObjectOrStixCoreRelationshipNoteCard);
