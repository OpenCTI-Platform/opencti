import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import { compose } from 'ramda';
import { createFragmentContainer, graphql } from 'react-relay';
import withStyles from '@mui/styles/withStyles';
import Grid from '@mui/material/Grid';
import Chip from '@mui/material/Chip';
import Card from '@common/card/Card';
import inject18n from '../../../../components/i18n';
import ItemLikelihood from '../../../../components/ItemLikelihood';
import MarkdownDisplay from '../../../../components/MarkdownDisplay';
import FieldOrEmpty from '../../../../components/FieldOrEmpty';
import Label from '../../../../components/common/label/Label';

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

class NoteDetailsComponent extends Component {
  render() {
    const { t, classes, note } = this.props;
    return (
      <div style={{ height: '100%' }}>
        <Card title={t('Entity details')}>
          <Grid container={true} spacing={3}>
            <Grid item xs={9}>
              <Label>
                {t('Abstract')}
              </Label>
              <MarkdownDisplay
                content={note.attribute_abstract}
                remarkGfmPlugin={true}
              />
              <Label
                sx={{ marginTop: 2 }}
              >
                {t('Content')}
              </Label>
              <MarkdownDisplay
                content={note.content}
                remarkGfmPlugin={true}
                commonmark={true}
              />
            </Grid>
            <Grid item xs={3}>
              <Label>
                {t('Note types')}
              </Label>
              <FieldOrEmpty source={note.note_types}>
                {note.note_types?.map((noteType) => (
                  <Chip
                    key={noteType}
                    classes={{ root: classes.chip }}
                    label={noteType}
                    color="primary"
                  />
                ))}
              </FieldOrEmpty>
              <Label
                sx={{ marginTop: 2 }}
              >
                {t('Likelihood')}
              </Label>
              <ItemLikelihood likelihood={note.likelihood} />
            </Grid>
          </Grid>
        </Card>
      </div>
    );
  }
}

NoteDetailsComponent.propTypes = {
  note: PropTypes.object,
  classes: PropTypes.object,
  t: PropTypes.func,
  fld: PropTypes.func,
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

export default compose(inject18n, withStyles(styles))(NoteDetails);
