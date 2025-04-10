import React, { FunctionComponent, useState } from 'react';
import { graphql, useFragment } from 'react-relay';
import { Link } from 'react-router-dom';
import { OpenInNewOutlined } from '@mui/icons-material';
import Card from '@mui/material/Card';
import CardContent from '@mui/material/CardContent';
import CardHeader from '@mui/material/CardHeader';
import Typography from '@mui/material/Typography';
import Grid from '@mui/material/Grid';
import Dialog from '@mui/material/Dialog';
import DialogContent from '@mui/material/DialogContent';
import DialogContentText from '@mui/material/DialogContentText';
import DialogActions from '@mui/material/DialogActions';
import Button from '@mui/material/Button';
import IconButton from '@mui/material/IconButton';
import makeStyles from '@mui/styles/makeStyles';
import { useTheme } from '@mui/styles';
import Chip from '@mui/material/Chip';
import { useFormatter } from '../../../../components/i18n';
import { noteMutationRelationDelete } from './AddNotesLines';
import NotePopover from './NotePopover';
import { resolveLink } from '../../../../utils/Entity';
import { CollaborativeSecurity } from '../../../../utils/Security';
import { KNOWLEDGE_KNUPDATE } from '../../../../utils/hooks/useGranted';
import type { Theme } from '../../../../components/Theme';
import { deleteNode } from '../../../../utils/store';
import { StixCoreObjectOrStixCoreRelationshipNotesCardsQuery$variables } from './__generated__/StixCoreObjectOrStixCoreRelationshipNotesCardsQuery.graphql';
import { StixCoreObjectOrStixCoreRelationshipNoteCard_node$key } from './__generated__/StixCoreObjectOrStixCoreRelationshipNoteCard_node.graphql';
import Transition from '../../../../components/Transition';
import ItemConfidence from '../../../../components/ItemConfidence';
import StixCoreObjectLabelsView from '../../common/stix_core_objects/StixCoreObjectLabelsView';
import ItemLikelihood from '../../../../components/ItemLikelihood';
import ItemMarkings from '../../../../components/ItemMarkings';
import MarkdownDisplay from '../../../../components/MarkdownDisplay';
import useApiMutation from '../../../../utils/hooks/useApiMutation';

// Deprecated - https://mui.com/system/styles/basics/
// Do not use it for new code.
const useStyles = makeStyles<Theme>((theme) => ({
  card: {
    width: '100%',
    height: '100%',
    marginBottom: 30,
    borderRadius: 4,
    padding: 0,
    position: 'relative',
  },
  chipInList: {
    fontSize: 12,
    height: 20,
    float: 'left',
    width: 120,
    marginRight: 10,
  },
  external: {
    position: 'absolute',
    bottom: 0,
    right: 0,
    color: theme.palette.text?.secondary,
  },
}));

const StixCoreObjectOrStixCoreRelationshipNoteCardFragment = graphql`
  fragment StixCoreObjectOrStixCoreRelationshipNoteCard_node on Note {
    id
    attribute_abstract
    entity_type
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
      id
      definition_type
      definition
      x_opencti_order
      x_opencti_color
    }
    objectLabel {
      id
      value
      color
    }
  }
`;

interface StixCoreObjectOrStixCoreRelationshipNoteCardComponentProps {
  data: StixCoreObjectOrStixCoreRelationshipNoteCard_node$key;
  stixCoreObjectOrStixCoreRelationshipId: string;
  paginationOptions: StixCoreObjectOrStixCoreRelationshipNotesCardsQuery$variables;
}

const StixCoreObjectOrStixCoreRelationshipNoteCard: FunctionComponent<
StixCoreObjectOrStixCoreRelationshipNoteCardComponentProps
> = ({ data, stixCoreObjectOrStixCoreRelationshipId, paginationOptions }) => {
  const { t_i18n, nsdt } = useFormatter();
  const classes = useStyles();
  const theme = useTheme<Theme>();
  const note = useFragment(
    StixCoreObjectOrStixCoreRelationshipNoteCardFragment,
    data,
  );
  const [displayDialog, setDisplayDialog] = useState<boolean>(false);
  const [removing, setRemoving] = useState<boolean>(false);
  const handleOpenDialog = () => setDisplayDialog(true);
  const handleCloseDialog = () => {
    setDisplayDialog(false);
    setRemoving(false);
  };
  const [commit] = useApiMutation(noteMutationRelationDelete);
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
    authorLink = `${resolveLink(note.createdBy.entity_type)}/${
      note.createdBy.id
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
          <CollaborativeSecurity data={note} needs={[KNOWLEDGE_KNUPDATE]}>
            <NotePopover
              id={note.id}
              note={note}
              handleOpenRemoveExternal={handleOpenDialog}
              size="small"
              paginationOptions={paginationOptions}
              variant="inLine"
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
                  t_i18n('Unknown')
                )}
              </strong>{' '}
              <span style={{ color: theme.palette.text?.secondary }}>
                {t_i18n('added a note')} {t_i18n('on')} {nsdt(note.created)}
              </span>
            </div>
            <div
              style={{
                float: 'left',
                marginLeft: 20,
                textTransform: 'none',
              }}
            >
              {(note.note_types ?? [t_i18n('Unknown')]).map((type) => (
                <Chip
                  key={type}
                  classes={{ root: classes.chipInList }}
                  color="primary"
                  variant="outlined"
                  label={t_i18n(type)}
                />
              ))}
            </div>
            <div
              style={{
                float: 'right',
                textTransform: 'none',
              }}
            >
              <ItemMarkings
                variant="inList"
                markingDefinitions={note.objectMarking ?? []}
                limit={1}
              />
            </div>
          </div>
        }
      />
      <CardContent>
        <Grid container={true} spacing={3}>
          <Grid item xs={9}>
            <Typography variant="h3" gutterBottom={true}>
              {t_i18n('Abstract')}
            </Typography>
            {note.attribute_abstract && (
              <MarkdownDisplay
                content={note.attribute_abstract}
                remarkGfmPlugin={true}
              />
            )}
            <Typography
              variant="h3"
              gutterBottom={true}
              style={{ marginTop: 20 }}
            >
              {t_i18n('Content')}
            </Typography>
            {note.content && (
              <MarkdownDisplay content={note.content} remarkGfmPlugin={true} />
            )}
          </Grid>
          <Grid item xs={3}>
            <StixCoreObjectLabelsView
              labels={note.objectLabel}
              id={note.id}
              entity_type={note.entity_type}
            />
            <Grid container={true} spacing={3}>
              <Grid item xs={6}>
                <Typography
                  variant="h3"
                  gutterBottom={true}
                  style={{ marginTop: 20 }}
                >
                  {t_i18n('Confidence level')}
                </Typography>
                <ItemConfidence
                  confidence={note.confidence}
                  entityType={note.entity_type}
                />
              </Grid>
              <Grid item xs={6}>
                <Typography
                  variant="h3"
                  gutterBottom={true}
                  style={{ marginTop: 20 }}
                >
                  {t_i18n('Likelihood')}
                </Typography>
                <ItemLikelihood likelihood={note.likelihood} />
              </Grid>
            </Grid>
          </Grid>
        </Grid>
        <IconButton
          component={Link}
          to={`/dashboard/analyses/notes/${note.id}`}
          classes={{ root: classes.external }}
          size="large"
        >
          <OpenInNewOutlined fontSize="small" />
        </IconButton>
      </CardContent>
      <Dialog
        open={displayDialog}
        slotProps={{ paper: { elevation: 1 } }}
        keepMounted={true}
        slots={{ transition: Transition }}
        onClose={handleCloseDialog}
      >
        <DialogContent>
          <DialogContentText>
            {t_i18n('Do you want to remove this note from this entity?')}
          </DialogContentText>
        </DialogContent>
        <DialogActions>
          <Button onClick={handleCloseDialog} disabled={removing}>
            {t_i18n('Cancel')}
          </Button>
          <Button onClick={handleRemoval} color="secondary" disabled={removing}>
            {t_i18n('Remove')}
          </Button>
        </DialogActions>
      </Dialog>
    </Card>
  );
};

export default StixCoreObjectOrStixCoreRelationshipNoteCard;
