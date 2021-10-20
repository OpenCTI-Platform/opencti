import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import { compose } from 'ramda';
import { createFragmentContainer } from 'react-relay';
import graphql from 'babel-plugin-relay/macro';
import { withStyles } from '@material-ui/core/styles';
import Paper from '@material-ui/core/Paper';
import Typography from '@material-ui/core/Typography';
import Grid from '@material-ui/core/Grid';
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

class ExternalReferenceDetailsComponent extends Component {
  render() {
    const {
      t, fldt, classes, externalReference,
    } = this.props;
    return (
      <div style={{ height: '100%' }}>
        <Typography variant="h4" gutterBottom={true}>
          {t('Details')}
        </Typography>
        <Paper classes={{ root: classes.paper }} elevation={2}>
          <Grid container={true} spacing={3}>
            <Grid item={true} xs={6}>
              <Typography variant="h3" gutterBottom={true}>
                {t('External ID')}
              </Typography>
              {externalReference.external_id}
            </Grid>
            <Grid item={true} xs={6}>
              <Typography variant="h3" gutterBottom={true}>
                {t('URL')}
              </Typography>
              <pre>{externalReference.url}</pre>
            </Grid>
          </Grid>
        </Paper>
      </div>
    );
  }
}

ExternalReferenceDetailsComponent.propTypes = {
  externalReference: PropTypes.object,
  classes: PropTypes.object,
  t: PropTypes.func,
  fld: PropTypes.func,
};

const ExternalReferenceDetails = createFragmentContainer(
  ExternalReferenceDetailsComponent,
  {
    externalReference: graphql`
      fragment ExternalReferenceDetails_externalReference on ExternalReference {
        id
        external_id
        url
      }
    `,
  },
);

export default compose(inject18n, withStyles(styles))(ExternalReferenceDetails);
