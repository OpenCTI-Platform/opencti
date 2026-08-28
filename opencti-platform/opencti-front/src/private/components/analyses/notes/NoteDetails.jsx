import React from 'react';
import * as PropTypes from 'prop-types';
import { compose } from 'ramda';
import { createFragmentContainer, graphql } from 'react-relay';
import withStyles from '@mui/styles/withStyles';
import Grid from '@mui/material/Grid';
import Card from '@common/card/Card';
import { useFormatter } from '../../../../components/i18n';
import ItemLikelihood from '../../../../components/ItemLikelihood';
import MarkdownDisplay from '../../../../components/markdownDisplay/MarkdownDisplay';
import FieldOrEmpty from '../../../../components/FieldOrEmpty';
import Label from '../../../../components/common/label/Label';
import Tag from '@common/tag/Tag';
import { Stack } from '@mui/material';
import { resolveNoteEmbeddedImageUrl } from './note-utils';

const styles = (theme) => ({
  chip: {
    fontSize: 12,
    lineHeight: '12px',
    backgroundColor: theme.palette.background.accent,
    color: theme.palette.text.primary,
    textTransform: 'uppercase',
    borderRadius: 4,
    margin: '0 5px 5px 0',
  },
});

const NoteDetailsComponent = (props) => {
  const { t_i18n } = useFormatter();
  const { note } = props;
  const noteImageResolver = (url) => resolveNoteEmbeddedImageUrl(url, note.id);

  return (
    <div style={{ height: '100%' }}>
      <Card title={t_i18n('Entity details')}>
        <Grid container={true} spacing={3}>
          <Grid item xs={9}>
            <Label>
              {t_i18n('Abstract')}
            </Label>
            <MarkdownDisplay
              content={note.attribute_abstract}
              remarkGfmPlugin={true}
              resolveImageUrl={noteImageResolver}
            />
            <Label
              sx={{ marginTop: 2 }}
            >
              {t_i18n('Content')}
            </Label>
            <MarkdownDisplay
              content={note.content}
              remarkGfmPlugin={true}
              commonmark={true}
              resolveImageUrl={noteImageResolver}
            />
          </Grid>
          <Grid item xs={3}>
            <Label>
              {t_i18n('Note types')}
            </Label>
            <FieldOrEmpty source={note.note_types}>
              <Stack direction="row" flexWrap="wrap" gap={1}>
                {note.note_types?.map((noteType) => (
                  <Tag
                    key={noteType}
                    label={noteType}
                  />
                ))}
              </Stack>
            </FieldOrEmpty>
            <Label
              sx={{ marginTop: 2 }}
            >
              {t_i18n('Likelihood')}
            </Label>
            <ItemLikelihood likelihood={note.likelihood} />
          </Grid>
        </Grid>
      </Card>
    </div>
  );
};

NoteDetailsComponent.propTypes = {
  note: PropTypes.object,
  classes: PropTypes.object,
};

const NoteDetails = createFragmentContainer(NoteDetailsComponent, {
  note: graphql`
    fragment NoteDetails_note on Note {
      id
      attribute_abstract
      content
      note_types
      likelihood
    }
  `,
});

export default compose(withStyles(styles))(NoteDetails);
