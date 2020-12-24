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
import EntityStixCoreRelationshipsDonut from '../../common/stix_core_relationships/EntityStixCoreRelationshipsDonut';
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

class XOpenCTIIncidentDetailsComponent extends Component {
  render() {
    const {
      fld, t, classes, xOpenCTIIncident,
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
                {t('Description')}
              </Typography>
              <ExpandableMarkdown
                source={xOpenCTIIncident.description}
                limit={400}
              />
            </Grid>
            <Grid item={true} xs={6}>
              <Typography variant="h3" gutterBottom={true}>
                {t('First seen')}
              </Typography>
              {fld(xOpenCTIIncident.first_seen)}
              <Typography
                variant="h3"
                gutterBottom={true}
                style={{ marginTop: 20 }}
              >
                {t('Last seen')}
              </Typography>
              {fld(xOpenCTIIncident.last_seen)}
              <Typography
                variant="h3"
                gutterBottom={true}
                style={{ marginTop: 20 }}
              >
                {t('Objective')}
              </Typography>
              <ExpandableMarkdown
                source={xOpenCTIIncident.objective}
                limit={100}
              />
            </Grid>
          </Grid>
          <EntityStixCoreRelationshipsDonut
            entityId={xOpenCTIIncident.id}
            entityType="Stix-Cyber-Observable"
            relationshipType="related-to"
            field="entity_type"
            height={200}
            variant="inLine"
            isTo={true}
          />
        </Paper>
      </div>
    );
  }
}

XOpenCTIIncidentDetailsComponent.propTypes = {
  xOpenCTIIncident: PropTypes.object,
  classes: PropTypes.object,
  t: PropTypes.func,
  fld: PropTypes.func,
};

const XOpenCTIXOpenCTIIncidentDetails = createFragmentContainer(
  XOpenCTIIncidentDetailsComponent,
  {
    xOpenCTIIncident: graphql`
      fragment XOpenCTIIncidentDetails_xOpenCTIIncident on XOpenCTIIncident {
        id
        first_seen
        last_seen
        objective
        description
      }
    `,
  },
);

export default compose(
  inject18n,
  withStyles(styles),
)(XOpenCTIXOpenCTIIncidentDetails);
