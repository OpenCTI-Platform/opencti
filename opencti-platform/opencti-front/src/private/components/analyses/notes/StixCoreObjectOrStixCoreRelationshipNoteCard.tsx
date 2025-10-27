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
import DialogTitle from '@mui/material/DialogTitle';
import { Stack } from '@mui/material';
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

  const authorName = note.createdBy ? note.createdBy.name : null;
  const authorLink = note.createdBy ? `${resolveLink(note.createdBy.entity_type)}/${note.createdBy.id}` : null;

  return (
    <Card
      sx={{
        marginBottom: 2,
      }}
      variant="outlined"
    >
      <CardHeader
        style={{
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
            />
          </CollaborativeSecurity>
        }
        title={
          <Stack direction="row" alignItems="center" justifyContent="space-between" spacing={1} sx={{ marginTop: 0.5 }}>
            <Stack direction="row" spacing={1}>
              <Stack direction="row" spacing={0.5} sx={{ textTransform: 'none' }}>
                <Typography variant='body2' sx={{ fontWeight: 800 }}>
                  {authorLink ? <Link to={authorLink}>{authorName}</Link> : t_i18n('Unknown')}
                </Typography>
                <Typography variant='body2' sx={{ color: theme.palette.text?.secondary }}>
                  {t_i18n('added a note')} {t_i18n('on')} {nsdt(note.created)}
                </Typography>
              </Stack>

              <Stack direction="row" spacing={1}>
                {(note.note_types ?? [t_i18n('Unknown')]).map((type) => (
                  <Chip
                    key={type}
                    color="primary"
                    variant="outlined"
                    label={t_i18n(type)}
                    sx={{
                      fontSize: 12,
                      height: 20,
                      width: 120,
                    }}
                  />
                ))}
              </Stack>
            </Stack>

            <ItemMarkings
              variant="inList"
              markingDefinitions={note.objectMarking ?? []}
              limit={1}
            />
          </Stack>
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
        <DialogTitle>
          {t_i18n('Are you sure?')}
        </DialogTitle>
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
            {t_i18n('Confirm')}
          </Button>
        </DialogActions>
      </Dialog>
    </Card>
  );
};

export default StixCoreObjectOrStixCoreRelationshipNoteCard;
