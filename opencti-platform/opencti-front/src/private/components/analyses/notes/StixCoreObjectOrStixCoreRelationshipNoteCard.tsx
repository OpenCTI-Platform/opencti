import { FunctionComponent } from 'react';
import { graphql, useFragment } from 'react-relay';
import { Link } from 'react-router-dom';
import { OpenInNewOutlined } from '@mui/icons-material';
import Typography from '@mui/material/Typography';
import Grid from '@mui/material/Grid2';
import IconButton from '@common/button/IconButton';
import { useTheme } from '@mui/styles';
import { Stack, Box } from '@mui/material';
import { useFormatter } from '../../../../components/i18n';
import NotePopover from './NotePopover';
import { resolveLink } from '../../../../utils/Entity';
import { CollaborativeSecurity } from '../../../../utils/Security';
import { KNOWLEDGE_KNUPDATE } from '../../../../utils/hooks/useGranted';
import type { Theme } from '../../../../components/Theme';
import { StixCoreObjectOrStixCoreRelationshipNotesCardsQuery$variables } from './__generated__/StixCoreObjectOrStixCoreRelationshipNotesCardsQuery.graphql';
import { StixCoreObjectOrStixCoreRelationshipNoteCard_node$key } from './__generated__/StixCoreObjectOrStixCoreRelationshipNoteCard_node.graphql';
import ItemConfidence from '../../../../components/ItemConfidence';
import StixCoreObjectLabelsView from '../../common/stix_core_objects/StixCoreObjectLabelsView';
import ItemLikelihood from '../../../../components/ItemLikelihood';
import MarkdownDisplay from '../../../../components/MarkdownDisplay';
import Card from '../../../../components/common/card/Card';
import FieldOrEmpty from '../../../../components/FieldOrEmpty';
import Label from '../../../../components/common/label/Label';
import ItemMarkings from '../../../../components/ItemMarkings';
import Tag from '../../../../components/common/tag/Tag';

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
    ...NotePopoverFragment
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
  const theme = useTheme<Theme>();

  const note = useFragment(
    StixCoreObjectOrStixCoreRelationshipNoteCardFragment,
    data,
  );

  const authorName = note.createdBy ? note.createdBy.name : null;
  const authorLink = note.createdBy ? `${resolveLink(note.createdBy.entity_type)}/${note.createdBy.id}` : null;

  return (
    <Card>
      <Stack
        direction="row"
        alignItems="center"
        justifyContent="space-between"
        sx={{
          borderBottom: '1px solid',
          borderColor: theme.palette.border.main,
          pb: 2,
          mb: 2,
        }}
      >
        <Stack
          direction="row"
          spacing={0.5}
          sx={{ textTransform: 'none' }}
        >
          <Typography variant="body1" sx={{ fontWeight: 800 }}>
            {authorLink
              ? <Link to={authorLink}>{authorName}</Link>
              : t_i18n('Unknown')
            }
          </Typography>
          <Typography variant="body1" sx={{ color: theme.palette.text.light }}>
            {t_i18n('added a note on', { values: { date: nsdt(note.created) } })}
          </Typography>
        </Stack>

        <div>
          <IconButton
            component={Link}
            to={`/dashboard/analyses/notes/${note.id}`}
            sx={{ mr: 1 }}
          >
            <OpenInNewOutlined fontSize="small" />
          </IconButton>
          <CollaborativeSecurity data={note} needs={[KNOWLEDGE_KNUPDATE]}>
            <NotePopover
              data={note}
              paginationOptions={paginationOptions}
              entityId={stixCoreObjectOrStixCoreRelationshipId}
            />
          </CollaborativeSecurity>
        </div>
      </Stack>

      <Grid container spacing={3}>
        <Grid size={{ xs: 8 }} gap={3}>
          <Box>
            <Label>{t_i18n('Abstract')}</Label>
            <FieldOrEmpty source={note.attribute_abstract}>
              <MarkdownDisplay
                content={note.attribute_abstract ?? null}
                remarkGfmPlugin
              />
            </FieldOrEmpty>
          </Box>
          <Box sx={{ mt: 2 }}>
            <Label>{t_i18n('Content')}</Label>
            <FieldOrEmpty source={note.content}>
              <MarkdownDisplay
                content={note.content}
                remarkGfmPlugin
              />
            </FieldOrEmpty>
          </Box>
        </Grid>

        <Grid size={{ xs: 2 }}>
          <Box>
            <Label>{t_i18n('Marking')}</Label>
            <ItemMarkings
              markingDefinitions={note.objectMarking ?? []}
              limit={2}
            />
          </Box>
          <Box sx={{ mt: 2 }}>
            <Label>{t_i18n('Confidence level')}</Label>
            <ItemConfidence
              confidence={note.confidence}
              entityType={note.entity_type}
            />
          </Box>
          <Box sx={{ mt: 2 }}>
            <Label>{t_i18n('Likelihood')}</Label>
            <ItemLikelihood likelihood={note.likelihood} />
          </Box>
        </Grid>

        <Grid size={{ xs: 2 }}>
          <Box>
            <Label>{t_i18n('Note type')}</Label>
            <FieldOrEmpty source={note.note_types}>
              <Stack direction="row" spacing={1}>
                {note.note_types?.map((type) => (
                  <Tag
                    key={type}
                    label={t_i18n(type)}
                  />
                ))}
              </Stack>
            </FieldOrEmpty>
          </Box>
          <Box sx={{ mt: 2 }}>
            <StixCoreObjectLabelsView
              labels={note.objectLabel}
              id={note.id}
              entity_type={note.entity_type}
            />
          </Box>
        </Grid>
      </Grid>
    </Card>
  );
};

export default StixCoreObjectOrStixCoreRelationshipNoteCard;
