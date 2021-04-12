import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import {
  compose, pathOr, take, propOr,
} from 'ramda';
import { createFragmentContainer } from 'react-relay';
import Markdown from 'react-markdown';
import graphql from 'babel-plugin-relay/macro';
import { withStyles } from '@material-ui/core/styles';
import Card from '@material-ui/core/Card';
import CardContent from '@material-ui/core/CardContent';
import Typography from '@material-ui/core/Typography';
import { AccountCircleOutlined, LinkOff } from '@material-ui/icons';
import { ClockOutline } from 'mdi-material-ui';
import { Link } from 'react-router-dom';
import CardActionArea from '@material-ui/core/CardActionArea';
import Divider from '@material-ui/core/Divider';
import IconButton from '@material-ui/core/IconButton';
import { ConnectionHandler } from 'relay-runtime';
import Dialog from '@material-ui/core/Dialog';
import DialogContent from '@material-ui/core/DialogContent';
import DialogContentText from '@material-ui/core/DialogContentText';
import DialogActions from '@material-ui/core/DialogActions';
import Button from '@material-ui/core/Button';
import Slide from '@material-ui/core/Slide';
import inject18n from '../../../../components/i18n';
import ItemMarking from '../../../../components/ItemMarking';
import StixCoreObjectLabels from '../../common/stix_core_objects/StixCoreObjectLabels';
import { commitMutation } from '../../../../relay/environment';
import { noteMutationRelationDelete } from './AddNotesLines';
import { truncate } from '../../../../utils/String';

const styles = (theme) => ({
  card: {
    width: '100%',
    height: '100%',
    borderRadius: 6,
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
      removeNote: null,
      removing: false,
    };
  }

  handleOpenDialog(externalReferenceEdge, event) {
    event.preventDefault();
    const openedState = {
      displayDialog: true,
      removeNote: externalReferenceEdge,
    };
    this.setState(openedState);
  }

  handleCloseDialog() {
    const closedState = {
      displayDialog: false,
      removeNote: null,
    };
    this.setState(closedState);
  }

  handleRemoval() {
    this.setState({ removing: true });
    this.removeNote(this.state.removeNote);
  }

  removeNote(note) {
    commitMutation({
      mutation: noteMutationRelationDelete,
      variables: {
        id: note.id,
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
        ConnectionHandler.deleteNode(conn, note.id);
      },
      onCompleted: () => {
        this.setState({ removing: false });
        this.handleCloseDialog();
      },
    });
  }

  render() {
    const {
      nsdt, classes, node, t,
    } = this.props;
    return (
      <Card classes={{ root: classes.card }} raised={false} variant="outlined">
        <CardActionArea
          classes={{ root: classes.area }}
          component={Link}
          to={`/dashboard/analysis/notes/${node.id}`}
        >
          <CardContent style={{ paddingBottom: 10, position: 'relative' }}>
            <div style={{ width: '100%', height: 80, paddingTop: 5 }}>
              <div style={{ float: 'left', width: '50%' }}>
                <AccountCircleOutlined
                  fontSize="small"
                  style={{ float: 'left', marginRight: 5 }}
                />
                <Typography variant="body2" style={{ paddingTop: 2 }}>
                  {propOr('-', 'name', node.createdBy)}
                </Typography>
              </div>
              <div style={{ float: 'right', marginTop: -15 }}>
                <IconButton
                  aria-label="Remove"
                  onClick={this.handleOpenDialog.bind(this, node)}
                >
                  <LinkOff />
                </IconButton>
              </div>
              <div className="clearfix" />
              <div style={{ float: 'left', width: '50%' }}>
                <ClockOutline
                  fontSize="small"
                  style={{ float: 'left', marginRight: 5 }}
                />
                <Typography variant="body2" style={{ paddingTop: 2 }}>
                  {nsdt(node.created)}
                </Typography>
              </div>
              <div style={{ float: 'right' }}>
                {take(1, pathOr([], ['objectMarking', 'edges'], node)).map(
                  (markingDefinition) => (
                    <ItemMarking
                      key={markingDefinition.node.id}
                      label={markingDefinition.node.definition}
                      color={markingDefinition.node.x_opencti_color}
                    />
                  ),
                )}
              </div>
              <div className="clearfix" />
            </div>
            <Divider variant="fullWidth" />
            <Typography
              variant="h3"
              gutterBottom={true}
              style={{ marginTop: 20 }}
            >
              {t('Abstract')}
            </Typography>
            <Typography
              variant="body2"
              noWrap={true}
              style={{ margin: '10px 0 10px 0', fontWeight: 500 }}
            >
              <Markdown className="markdown" source={node.attribute_abstract} />
            </Typography>
            <Typography
              variant="h3"
              gutterBottom={true}
              style={{ marginTop: 20 }}
            >
              {t('Content')}
            </Typography>
            <Typography variant="body2" style={{ marginBottom: 20 }}>
              <Markdown
                className="markdown"
                source={truncate(node.content, 200)}
              />
            </Typography>
            <div className={classes.objectLabel}>
              <StixCoreObjectLabels labels={node.objectLabel} />
            </div>
          </CardContent>
        </CardActionArea>
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
  withStyles(styles),
)(StixCoreObjectOrStixCoreRelationshipNoteCard);
