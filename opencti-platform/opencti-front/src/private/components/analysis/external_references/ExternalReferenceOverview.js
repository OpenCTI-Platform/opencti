import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import { compose } from 'ramda';
import { graphql, createFragmentContainer } from 'react-relay';
import withStyles from '@mui/styles/withStyles';
import Paper from '@mui/material/Paper';
import Typography from '@mui/material/Typography';
import Grid from '@mui/material/Grid';
import inject18n from '../../../../components/i18n';
import ExpandableMarkdown from '../../../../components/ExpandableMarkdown';

const styles = () => ({
  paper: {
    height: '100%',
    minHeight: '100%',
    margin: '10px 0 0 0',
    padding: '15px',
    borderRadius: 6,
  },
});

class ExternalReferenceOverviewComponent extends Component {
  render() {
    const { t, fldt, classes, externalReference } = this.props;
    return (
      <div style={{ height: '100%' }}>
        <Typography variant="h4" gutterBottom={true}>
          {t('Overview')}
        </Typography>
        <Paper classes={{ root: classes.paper }} variant="outlined">
          <Grid container={true} spacing={3}>
            <Grid item={true} xs={6}>
              <Typography variant="h3" gutterBottom={true}>
                {t('Source name')}
              </Typography>
              {externalReference.source_name}
              <Typography
                variant="h3"
                gutterBottom={true}
                style={{ marginTop: 20 }}
              >
                {t('Description')}
              </Typography>
              <ExpandableMarkdown
                source={externalReference.description}
                limit={400}
              />
            </Grid>
            <Grid item={true} xs={6}>
              <Typography variant="h3" gutterBottom={true}>
                {t('Creation date')}
              </Typography>
              {fldt(externalReference.created)}
              <Typography
                variant="h3"
                gutterBottom={true}
                style={{ marginTop: 20 }}
              >
                {t('Modification date')}
              </Typography>
              {fldt(externalReference.modified)}
            </Grid>
          </Grid>
        </Paper>
      </div>
    );
  }
}

ExternalReferenceOverviewComponent.propTypes = {
  externalReference: PropTypes.object,
  classes: PropTypes.object,
  t: PropTypes.func,
  fld: PropTypes.func,
};

const ExternalReferenceOverview = createFragmentContainer(
  ExternalReferenceOverviewComponent,
  {
    externalReference: graphql`
      fragment ExternalReferenceOverview_externalReference on ExternalReference {
        id
        source_name
        description
        url
        created
        modified
      }
    `,
  },
);

export default compose(
  inject18n,
  withStyles(styles),
)(ExternalReferenceOverview);
