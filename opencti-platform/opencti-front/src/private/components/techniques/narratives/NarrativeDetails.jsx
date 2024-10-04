import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import * as R from 'ramda';
import { graphql, createFragmentContainer } from 'react-relay';
import withStyles from '@mui/styles/withStyles';
import Paper from '@mui/material/Paper';
import Typography from '@mui/material/Typography';
import Grid from '@mui/material/Grid';
import inject18n from '../../../../components/i18n';
import ExpandableMarkdown from '../../../../components/ExpandableMarkdown';
import NarrativeParentNarratives from './NarrativeParentNarratives';
import NarrativeSubNarratives from './NarrativeSubNarratives';

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

class NarrativeDetailsComponent extends Component {
  render() {
    const { t, classes, narrative } = this.props;
    return (
      <div style={{ height: '100%' }}>
        <Typography variant="h4" gutterBottom={true}>
          {t('Details')}
        </Typography>
        <Paper classes={{ root: classes.paper }} className={'paper-for-grid'} variant="outlined">
          <Grid container={true} spacing={3}>
            <Grid item xs={6}>
              <Typography variant="h3" gutterBottom={true}>
                {t('Description')}
              </Typography>
              <ExpandableMarkdown source={narrative.description} limit={400} />
            </Grid>
            <Grid item xs={6}>
              {narrative.isSubNarrative ? (
                <NarrativeParentNarratives narrative={narrative} />
              ) : (
                <NarrativeSubNarratives narrative={narrative} />
              )}
            </Grid>
          </Grid>
        </Paper>
      </div>
    );
  }
}

NarrativeDetailsComponent.propTypes = {
  narrative: PropTypes.object,
  classes: PropTypes.object,
  t: PropTypes.func,
  fld: PropTypes.func,
};

const NarrativeDetails = createFragmentContainer(NarrativeDetailsComponent, {
  narrative: graphql`
    fragment NarrativeDetails_narrative on Narrative {
      id
      description
      isSubNarrative
      ...NarrativeSubNarratives_narrative
      ...NarrativeParentNarratives_narrative
    }
  `,
});

export default R.compose(inject18n, withStyles(styles))(NarrativeDetails);
