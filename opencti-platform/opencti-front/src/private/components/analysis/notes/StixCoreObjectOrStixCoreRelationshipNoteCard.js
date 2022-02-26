import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import { compose, pathOr, take } from 'ramda';
import { graphql, createFragmentContainer } from 'react-relay';
import { Link } from 'react-router-dom';
import Markdown from 'react-markdown';
import { OpenInNewOutlined } from '@mui/icons-material';
import withStyles from '@mui/styles/withStyles';
import withTheme from '@mui/styles/withTheme';
import Card from '@mui/material/Card';
import CardContent from '@mui/material/CardContent';
import CardHeader from '@mui/material/CardHeader';
import Typography from '@mui/material/Typography';
import { ConnectionHandler } from 'relay-runtime';
import Dialog from '@mui/material/Dialog';
import DialogContent from '@mui/material/DialogContent';
import DialogContentText from '@mui/material/DialogContentText';
import DialogActions from '@mui/material/DialogActions';
import Button from '@mui/material/Button';
import Slide from '@mui/material/Slide';
import IconButton from '@mui/material/IconButton';
import remarkGfm from 'remark-gfm';
import remarkParse from 'remark-parse';
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
    marginBottom: 30,
    borderRadius: 6,
    padding: 0,
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
    height: 61,
    display: '-webkit-box',
    '-webkit-box-orient': 'vertical',
    '-webkit-line-clamp': 2,
    overflow: 'hidden',
  },
  objectLabel: {
    height: 45,
    paddingTop: 15,
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

  handleRemoval() {
    this.setState({ removing: true });
    this.removeNote(this.state.noteIdToRemove);
  }

  removeNote(noteId) {
    commitMutation({
      mutation: noteMutationRelationDelete,
      variables: {
        id: noteId,
        toId: this.props.stixCoreObjectOrStixCoreRelationshipId,
        relationship_type: 'object',
      },
      updater: (store) => {
        const entity = store.get(
          this.props.stixCoreObjectOrStixCoreRelationshipId,
        );
        const conn = ConnectionHandler.getConnection(
          entity,
          'Pagination_notes',
        );
        ConnectionHandler.deleteNode(conn, noteId);
      },
      onCompleted: () => {
        this.setState({ removing: false });
        this.handleCloseDialog();
      },
    });
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
      authorLink = `${resolveLink(node.createdBy.entity_type)}/${
        node.createdBy.id
      }`;
    }
    return (
      <Card classes={{ root: classes.card }} variant="outlined">
        <CardHeader
          style={{
            padding: '15px 10px 10px 15px',
            borderBottom: `1px solid ${theme.palette.divider}`,
          }}
          action={
            <NotePopover
              id={node.id}
              entityId={stixCoreObjectOrStixCoreRelationshipId}
              handleOpenRemove={this.handleOpenDialog.bind(this)}
              size="small"
            />
          }
          title={
            <div>
              <div
                style={{
                  paddingTop: 2,
                  float: 'left',
                  fontDecoration: 'none',
                  textTransform: 'none',
                }}
              >
                <strong>
                  {authorLink ? (
                    <Link to={authorLink}>{authorName}</Link>
                  ) : (
                    t('Uknown')
                  )}
                </strong>{' '}
                <span style={{ color: theme.palette.text.secondary }}>
                  {t('added a note')} on {nsdt(node.created)}
                </span>
              </div>
              <div
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
              </div>
              <div
                style={{
                  float: 'right',
                  fontDecoration: 'none',
                  textTransform: 'none',
                }}
              >
                <StixCoreObjectLabels
                  variant="inList"
                  labels={node.objectLabel}
                />
              </div>
            </div>
          }
        />
        <CardContent>
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
          <Markdown
            remarkPlugins={[remarkGfm, remarkParse]}
            parserOptions={{ commonmark: true }}
            className="markdown"
          >
            {node.content}
          </Markdown>
          <IconButton
            component={Link}
            to={`/dashboard/analysis/notes/${node.id}`}
            classes={{ root: classes.external }}
            size="large"
          >
            <OpenInNewOutlined fontSize="small" />
          </IconButton>
        </CardContent>
        <Dialog
          open={this.state.displayDialog}
          PaperProps={{ elevation: 1 }}
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
              color="secondary"
              disabled={this.state.removing}
            >
              {t('Delete')}
            </Button>
          </DialogActions>
        </Dialog>
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
