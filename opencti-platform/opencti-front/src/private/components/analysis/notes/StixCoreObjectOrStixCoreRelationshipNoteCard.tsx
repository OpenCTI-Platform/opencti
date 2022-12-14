import React, { FunctionComponent, useState } from 'react';
import { graphql, useFragment, useMutation } from 'react-relay';
import { Link } from 'react-router-dom';
import Markdown from 'react-markdown';
import { OpenInNewOutlined } from '@mui/icons-material';
import Card from '@mui/material/Card';
import CardContent from '@mui/material/CardContent';
import CardHeader from '@mui/material/CardHeader';
import Typography from '@mui/material/Typography';
import Dialog from '@mui/material/Dialog';
import DialogContent from '@mui/material/DialogContent';
import DialogContentText from '@mui/material/DialogContentText';
import DialogActions from '@mui/material/DialogActions';
import Button from '@mui/material/Button';
import IconButton from '@mui/material/IconButton';
import remarkGfm from 'remark-gfm';
import remarkParse from 'remark-parse';
import makeStyles from '@mui/styles/makeStyles';
import { useTheme } from '@mui/styles';
import Tooltip from '@mui/material/Tooltip';
import { useFormatter } from '../../../../components/i18n';
import ItemMarking from '../../../../components/ItemMarking';
import StixCoreObjectLabels from '../../common/stix_core_objects/StixCoreObjectLabels';
import { noteMutationRelationDelete } from './AddNotesLines';
import NotePopover from './NotePopover';
import { resolveLink } from '../../../../utils/Entity';
import { CollaborativeSecurity } from '../../../../utils/Security';
import { KNOWLEDGE_KNUPDATE } from '../../../../utils/hooks/useGranted';
import { Theme } from '../../../../components/Theme';
import { deleteNode } from '../../../../utils/store';
import {
  StixCoreObjectOrStixCoreRelationshipNotesCardsQuery$variables,
} from './__generated__/StixCoreObjectOrStixCoreRelationshipNotesCardsQuery.graphql';
import {
  StixCoreObjectOrStixCoreRelationshipNoteCard_node$key,
} from './__generated__/StixCoreObjectOrStixCoreRelationshipNoteCard_node.graphql';
import Transition from '../../../../components/Transition';
import ItemConfidence from '../../../../components/ItemConfidence';

const useStyles = makeStyles<Theme>((theme) => ({
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
    backgroundColor: theme.palette.grey?.[600],
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
  cardFooter: {
    display: 'flex',
    alignItems: 'center',
    justifyContent: 'space-between',
  },
  itemConfidence: {
    position: 'absolute',
    right: 0,
  },
}));

const StixCoreObjectOrStixCoreRelationshipNoteCardFragment = graphql`
  fragment StixCoreObjectOrStixCoreRelationshipNoteCard_node on Note {
    id
    attribute_abstract
    content
    created
    modified
    confidence
    note_types
    likelihood
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
`;

interface StixCoreObjectOrStixCoreRelationshipNoteCardComponentProps {
  data: StixCoreObjectOrStixCoreRelationshipNoteCard_node$key
  stixCoreObjectOrStixCoreRelationshipId: string
  paginationOptions: StixCoreObjectOrStixCoreRelationshipNotesCardsQuery$variables
}

const StixCoreObjectOrStixCoreRelationshipNoteCard: FunctionComponent<StixCoreObjectOrStixCoreRelationshipNoteCardComponentProps> = ({
  data,
  stixCoreObjectOrStixCoreRelationshipId,
  paginationOptions,
}) => {
  const { t, nsdt } = useFormatter();
  const classes = useStyles();
  const theme = useTheme<Theme>();

  const note = useFragment(StixCoreObjectOrStixCoreRelationshipNoteCardFragment, data);
  const [displayDialog, setDisplayDialog] = useState<boolean>(false);
  const [removing, setRemoving] = useState<boolean>(false);

  const handleOpenDialog = () => setDisplayDialog(true);
  const handleCloseDialog = () => {
    setDisplayDialog(false);
    setRemoving(false);
  };

  const [commit] = useMutation(noteMutationRelationDelete);

  const removeNote = () => {
    commit({
      variables: {
        id: note.id,
        toId: stixCoreObjectOrStixCoreRelationshipId,
        relationship_type: 'object',
      },
      updater: (store) => {
        deleteNode(store, 'Pagination_notes', paginationOptions, note.id);
      },
      onCompleted: () => {
        setRemoving(false);
        handleCloseDialog();
      },
    });
  };

  const handleRemoval = () => {
    setRemoving(true);
    removeNote();
  };

  let authorName = null;
  let authorLink = null;
  if (note.createdBy) {
    authorName = note.createdBy.name;
    authorLink = `${resolveLink(note.createdBy.entity_type)}/${note.createdBy.id}`;
  }

  const [markingDefinition] = note.objectMarking?.edges ?? [];

  return (
    <Card classes={{ root: classes.card }} variant="outlined">
      <CardHeader style={{ padding: '15px 10px 10px 15px', borderBottom: `1px solid ${theme.palette.divider}` }}
                  action={
                    <CollaborativeSecurity data={note} needs={[KNOWLEDGE_KNUPDATE]}>
                      <NotePopover
                        id={note.id}
                        note={note}
                        handleOpenRemoveExternal={handleOpenDialog}
                        size="small"
                        paginationOptions={paginationOptions}
                      />
                    </CollaborativeSecurity>
                  }
                  title={
                    <div>
                      <div
                        style={{
                          paddingTop: 2,
                          float: 'left',
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
                        <span style={{ color: theme.palette.text?.secondary }}>
                          {t('added a note')}
                          {(note.note_types && note.note_types.length > 0)
                            && <b>&nbsp;({note.note_types?.join(',')})</b>
                          }
                          : {nsdt(note.created)}
                </span>
                      </div>
                      <div
                        style={{
                          float: 'left',
                          marginLeft: 20,
                          textTransform: 'none',
                        }}
                      >
                        {markingDefinition
                          && <ItemMarking
                            key={markingDefinition.node.id}
                            label={markingDefinition.node.definition}
                            color={markingDefinition.node.x_opencti_color}
                            variant="inList"
                          />
                        }
                      </div>
                      <div
                        style={{
                          float: 'right',
                          textTransform: 'none',
                        }}
                      >
                        <StixCoreObjectLabels
                          variant="inList"
                          labels={note.objectLabel}
                        />
                      </div>
                    </div>
                  }
      />
      <CardContent>
        <Tooltip title={t('Confidence level')}>
          <div className={classes.itemConfidence}>
            <ItemConfidence confidence={note.confidence} />
          </div>
        </Tooltip>
        <Typography
          variant="body2"
          noWrap={true}
          style={{ margin: '0 0 10px 0', fontWeight: 500 }}
        >
          {note.attribute_abstract
            && <Markdown
              remarkPlugins={[remarkGfm, remarkParse]}
              className="markdown"
            >
              {note.attribute_abstract}
            </Markdown>
          }
        </Typography>
        {note.content
          && <Markdown
            remarkPlugins={[remarkGfm, remarkParse]}
            className="markdown"
          >
            {note.content}
          </Markdown>
        }
        <div className={classes.cardFooter}>
          <div>
            {note.likelihood
              && <Tooltip title={t('Likelihood')}>
                <span>
                  {note.likelihood} %
                </span>
              </Tooltip>
            }
          </div>
          <IconButton
            component={Link}
            to={`/dashboard/analysis/notes/${note.id}`}
            size="large"
          >
            <OpenInNewOutlined fontSize="small" />
          </IconButton>
        </div>
      </CardContent>
      <Dialog
        open={displayDialog}
        PaperProps={{ elevation: 1 }}
        keepMounted={true}
        TransitionComponent={Transition}
        onClose={handleCloseDialog}
      >
        <DialogContent>
          <DialogContentText>
            {t('Do you want to remove this note from this entity?')}
          </DialogContentText>
        </DialogContent>
        <DialogActions>
          <Button
            onClick={handleCloseDialog}
            disabled={removing}
          >
            {t('Cancel')}
          </Button>
          <Button
            onClick={handleRemoval}
            color="secondary"
            disabled={removing}
          >
            {t('Remove')}
          </Button>
        </DialogActions>
      </Dialog>
    </Card>
  );
};

export default StixCoreObjectOrStixCoreRelationshipNoteCard;
