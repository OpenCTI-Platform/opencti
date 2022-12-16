/* eslint-disable */
/* refactor */
import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import { compose } from 'ramda';
// import { createFragmentContainer } from 'react-relay';
import { Link } from 'react-router-dom';
import Markdown from 'react-markdown';
import graphql from 'babel-plugin-relay/macro';
import { ExpandMoreOutlined, ExpandLessOutlined } from '@material-ui/icons';
import { withStyles, withTheme } from '@material-ui/core/styles';
import Card from '@material-ui/core/Card';
import Collapse from '@material-ui/core/Collapse';
import CardContent from '@material-ui/core/CardContent';
import CardHeader from '@material-ui/core/CardHeader';
import Divider from '@material-ui/core/Divider';
import Typography from '@material-ui/core/Typography';
import Grid from '@material-ui/core/Grid';
import Dialog from '@material-ui/core/Dialog';
import DialogContent from '@material-ui/core/DialogContent';
import DialogActions from '@material-ui/core/DialogActions';
import Button from '@material-ui/core/Button';
import Slide from '@material-ui/core/Slide';
import IconButton from '@material-ui/core/IconButton';
import remarkGfm from 'remark-gfm';
import remarkParse from 'remark-parse';
import rehypeRaw from 'rehype-raw';
import inject18n from '../../../../components/i18n';
import { commitMutation } from '../../../../relay/environment';
import CyioNotePopover from './CyioNotePopover';
import { resolveLink } from '../../../../utils/Entity';
import { toastGenericError } from '../../../../utils/bakedToast';
import { truncate } from '../../../../utils/String';

const styles = (theme) => ({
  card: {
    width: '100%',
    boxShadow: 'none',
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
  dialogActions: {
    justifyContent: 'flex-start',
    padding: '10px 0 20px 22px',
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

const cyioCoreObjectOrCyioCoreRelationshipNoteCardRemove = graphql`
  mutation CyioCoreObjectOrCyioCoreRelationshipNoteCardRemoveMutation(
    $fieldName: String!
    $fromId: ID!
    $toId: ID!
    $from_type: String
    $to_type: String!
  ) {
    removeReference(input:  {field_name: $fieldName, from_id: $fromId, to_id: $toId, from_type: $from_type, to_type: $to_type})
  }
`;

class CyioCoreObjectOrCyioCoreRelationshipNoteCardComponent extends Component {
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
    commitMutation({
      mutation: cyioCoreObjectOrCyioCoreRelationshipNoteCardRemove,
      variables: {
        toId: noteId,
        fromId: this.props.cyioCoreObjectOrCyioCoreRelationshipId,
        fieldName: this.props.fieldName,
        to_type: this.props.node.__typename,
        from_type: this.props.typename,
      },
      onCompleted: () => {
        this.setState({ removing: false });
        this.handleCloseDialog();
        this.props.refreshQuery();
      },
      onError: (err) => {
        console.error(err);
        return toastGenericError('Failed to remove Note');
      }
    });
    // commitMutation({
    //   mutation: noteMutationRelationDelete,
    //   variables: {
    //     id: noteId,
    //     toId: this.props.CyioCoreObjectOrCyioCoreRelationshipId,
    //     relationship_type: 'object',
    //   },
    //   updater: (store) => {
    //     const entity = store.get(
    //       this.props.CyioCoreObjectOrCyioCoreRelationshipId,
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
      refreshQuery,
      t,
      theme,
      CyioCoreObjectOrCyioCoreRelationshipId,
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
            <CyioNotePopover
              node={node}
              refreshQuery={refreshQuery}
              id={node.id}
              entityId={CyioCoreObjectOrCyioCoreRelationshipId}
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
                      t(node.abstract)
                    )}
                  </strong>
                  <span style={{ color: theme.palette.text.secondary }}>
                    {t(' added a note on ')}
                  </span>
                  {nsdt(node?.created)}
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
            </div>
          }
        />
        <CardContent style={{
          padding: '0 0 0 15px',
          // borderBottom: `1px solid ${theme.palette.divider}`,
        }}>
          {
            !this.state.open && (
              <Typography
                variant="body2"
                noWrap={true}
                style={{ margin: '0 0 10px 0', fontWeight: 500 }}
              >
                <Markdown
                  remarkPlugins={[remarkGfm, remarkParse]}
                  rehypePlugins={[rehypeRaw]}
                  parserOptions={{ commonmark: true }}
                  className="markdown"
                >
                  {node.content && truncate(t(node.content), 110)}
                </Markdown>
              </Typography>
            )
          }
        </CardContent>
        <Collapse in={this.state.open} timeout="auto" unmountOnExit>
          <CardContent style={{ padding: '0 20px 20px 15px' }}>
            <Grid container={true} spacing={3}>
              <Grid item={true} xs={6}>
                <Typography
                  variant="h3"
                  color="textSecondary"
                >
                  {t('Author')}
                </Typography>
                <Typography style={{ margin: '0 0 10px 0' }} align="left" variant="body2">
                  {t(node.authors)}
                </Typography>
              </Grid>
              <Grid item={true} xs={6}>
                <Typography
                  variant="h3"
                  color="textSecondary"
                >
                  {t('Abstract')}
                </Typography>
                <Typography style={{ margin: '0 0 10px 0' }} align="left" variant="body2">
                  {t(node.abstract)}
                </Typography>
              </Grid>
              <Grid item={true} xs={12}>
                <Typography
                  variant="h3"
                  color="textSecondary"
                >
                  {t('Content')}
                </Typography>
                <Typography style={{ margin: '0 0 10px 0' }} align="left" variant="body2">
                  <Markdown
                    remarkPlugins={[remarkGfm, remarkParse]}
                    rehypePlugins={[rehypeRaw]}
                    parserOptions={{ commonmark: true }}
                    className="markdown"
                  >
                    {t(node.content)}
                  </Markdown>
                </Typography>
              </Grid>
            </Grid>
          </CardContent>
        </Collapse>
        <Dialog
          open={this.state.displayDialog}
          keepMounted={true}
          TransitionComponent={Transition}
          onClose={this.handleCloseDialog.bind(this)}
        >
          <DialogContent>
            <Typography>
              {t('Do you want to remove this note?')}
            </Typography>
          </DialogContent>
          <DialogActions className={classes.dialogActions}>
            <Button
              onClick={this.handleCloseDialog.bind(this)}
              disabled={this.state.removing}
              variant='outlined'
              size='small'
            >
              {t('Cancel')}
            </Button>
            <Button
              onClick={this.handleRemoval.bind(this)}
              color='secondary'
              size='small'
              variant='contained'
              disabled={this.state.removing}
            >
              {t('Remove')}
            </Button>
          </DialogActions>
        </Dialog>
        <Divider light={true} />
      </Card>
    );
  }
}

CyioCoreObjectOrCyioCoreRelationshipNoteCardComponent.propTypes = {
  CyioCoreObjectOrCyioCoreRelationshipId: PropTypes.string,
  refreshQuery: PropTypes.func,
  node: PropTypes.object,
  classes: PropTypes.object,
  t: PropTypes.func,
  typename: PropTypes.string,
  nsdt: PropTypes.func,
};

// const CyioCoreObjectOrCyioCoreRelationshipNoteCard = createFragmentContainer(
//   CyioCoreObjectOrCyioCoreRelationshipNoteCardComponent,
//   {
//     node: graphql`
//       fragment CyioCoreObjectOrCyioCoreRelationshipNoteCard_node on CyioNote {
//         id
//         # attribute_abstract
//         content
//         created
//         modified
//         abstract
//         authors
//         # objectLabel {
//         #   edges {
//         #     node {
//         #       id
//         #       value
//         #       color
//         #     }
//         #   }
//         # }
//       }
//     `,
//   },
// );

export default compose(
  inject18n,
  withTheme,
  withStyles(styles),
)(CyioCoreObjectOrCyioCoreRelationshipNoteCardComponent);
