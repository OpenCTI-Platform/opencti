import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import { compose } from 'ramda';
import { createFragmentContainer, graphql } from 'react-relay';
import withStyles from '@mui/styles/withStyles';
import Paper from '@mui/material/Paper';
import Grid from '@mui/material/Grid';
import Typography from '@mui/material/Typography';
import Chip from '@mui/material/Chip';
import inject18n from '../../../../components/i18n';
import ItemLikelihood from '../../../../components/ItemLikelihood';
import MarkdownDisplay from '../../../../components/MarkdownDisplay';

const styles = (theme) => ({
  paper: {
    marginTop: theme.spacing(1),
    padding: '15px',
    borderRadius: 4,
  },
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
        <Typography variant="h4" gutterBottom={true}>
          {t('Entity details')}
        </Typography>
        <Paper classes={{ root: classes.paper }} className={'paper-for-grid'} variant="outlined">
          <Grid container={true} spacing={3}>
            <Grid item xs={9}>
              <Typography variant="h3" gutterBottom={true}>
                {t('Abstract')}
              </Typography>
              <MarkdownDisplay
                content={note.attribute_abstract}
                remarkGfmPlugin={true}
              />
              <Typography
                variant="h3"
                gutterBottom={true}
                style={{ marginTop: 20 }}
              >
                {t('Content')}
              </Typography>
              <MarkdownDisplay
                content={note.content}
                remarkGfmPlugin={true}
                commonmark={true}
              />
            </Grid>
            <Grid item xs={3}>
              <Typography variant="h3" gutterBottom={true}>
                {t('Note types')}
              </Typography>
              {note.note_types?.map((noteType) => (
                <Chip
                  key={noteType}
                  classes={{ root: classes.chip }}
                  label={noteType}
                  color="primary"
                />
              ))}
              <Typography
                variant="h3"
                gutterBottom={true}
                style={{ marginTop: 20 }}
              >
                {t('Likelihood')}
              </Typography>
              <ItemLikelihood likelihood={note.likelihood} />
            </Grid>
          </Grid>
        </Paper>
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
