import React, { Component } from 'react';
import PropTypes from 'prop-types';
import { compose } from 'ramda';
import { createFragmentContainer } from 'react-relay';
import graphql from 'babel-plugin-relay/macro';
import { withStyles } from '@material-ui/core/styles';
import Grid from '@material-ui/core/Grid';
import inject18n from '../../../../components/i18n';
import XOpenCTIIncidentOverview from './XOpenCTIIncidentOverview';
import XOpenCTIIncidentDetails from './XOpenCTIIncidentDetails';
import XOpenCTIIncidentEdition from './XOpenCTIIncidentEdition';
import XOpenCTIIncidentPopover from './XOpenCTIIncidentPopover';
import EntityLastReports from '../../reports/EntityLastReports';
import EntityReportsChart from '../../reports/EntityReportsChart';
import EntityStixCoreRelationshipsDonut from '../../common/stix_core_relationships/EntityStixCoreRelationshipsDonut';
import StixDomainObjectHeader from '../../common/stix_domain_objects/StixDomainObjectHeader';
import Security, { KNOWLEDGE_KNUPDATE } from '../../../../utils/Security';
import StixCoreObjectNotes from '../../common/stix_core_objects/StixCoreObjectNotes';

const styles = () => ({
  container: {
    margin: 0,
  },
  gridContainer: {
    marginBottom: 20,
  },
});

class XOpenCTIIncidentComponent extends Component {
  render() {
    const { classes, XOpenCTIIncident } = this.props;
    return (
      <div className={classes.container}>
        <StixDomainObjectHeader
          stixDomainObject={XOpenCTIIncident}
          PopoverComponent={<XOpenCTIIncidentPopover />}
        />
        <Grid
          container={true}
          spacing={3}
          classes={{ container: classes.gridContainer }}
        >
          <Grid item={true} xs={3}>
            <XOpenCTIIncidentOverview XOpenCTIIncident={XOpenCTIIncident} />
          </Grid>
          <Grid item={true} xs={3}>
            <XOpenCTIIncidentDetails XOpenCTIIncident={XOpenCTIIncident} />
          </Grid>
          <Grid item={true} xs={6}>
            <EntityLastReports entityId={XOpenCTIIncident.id} />
          </Grid>
        </Grid>
        <StixCoreObjectNotes entityId={XOpenCTIIncident.id} />
        <Grid
          container={true}
          spacing={3}
          classes={{ container: classes.gridContainer }}
          style={{ marginTop: 15 }}
        >
          <Grid item={true} xs={6}>
            <EntityStixCoreRelationshipsDonut
              entityId={XOpenCTIIncident.id}
              entityType="Stix-Observable"
              relationshipType="related-to"
              field="entity_type"
            />
          </Grid>
          <Grid item={true} xs={6}>
            <EntityReportsChart entityId={XOpenCTIIncident.id} />
          </Grid>
        </Grid>
        <Security needs={[KNOWLEDGE_KNUPDATE]}>
          <XOpenCTIIncidentEdition XOpenCTIIncidentId={XOpenCTIIncident.id} />
        </Security>
      </div>
    );
  }
}

XOpenCTIIncidentComponent.propTypes = {
  XOpenCTIIncident: PropTypes.object,
  classes: PropTypes.object,
  t: PropTypes.func,
};

const XOpenCTIXOpenCTIIncident = createFragmentContainer(
  XOpenCTIIncidentComponent,
  {
    XOpenCTIIncident: graphql`
      fragment XOpenCTIIncident_XOpenCTIIncident on XOpenCTIIncident {
        id
        name
        aliases
        ...XOpenCTIIncidentOverview_XOpenCTIIncident
        ...XOpenCTIIncidentDetails_XOpenCTIIncident
      }
    `,
  },
);

export default compose(inject18n, withStyles(styles))(XOpenCTIXOpenCTIIncident);
