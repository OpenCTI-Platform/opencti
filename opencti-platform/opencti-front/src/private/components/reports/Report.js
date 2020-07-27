import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import { compose } from 'ramda';
import { createFragmentContainer } from 'react-relay';
import graphql from 'babel-plugin-relay/macro';
import { withStyles } from '@material-ui/core/styles';
import Grid from '@material-ui/core/Grid';
import inject18n from '../../../components/i18n';
import ReportHeader from './ReportHeader';
import ReportOverview from './ReportOverview';
import ReportIdentity from './ReportDetails';
import ReportEdition from './ReportEdition';
import EntityExternalReferences from '../common/external_references/StixDomainObjectExternalReferences';
import EntityStixCoreRelationshipsDonut from '../common/stix_core_relationships/EntityStixCoreRelationshipsDonut';
import Security, { KNOWLEDGE_KNUPDATE } from '../../../utils/Security';
import StixCoreObjectNotes from '../common/stix_core_objects/StixCoreObjectNotes';

const styles = () => ({
  container: {
    margin: 0,
  },
  gridContainer: {
    marginBottom: 20,
  },
});

class ReportComponent extends Component {
  render() {
    const { classes, report } = this.props;
    return (
      <div className={classes.container}>
        <ReportHeader report={report} />
        <Grid
          container={true}
          spacing={3}
          classes={{ container: classes.gridContainer }}
        >
          <Grid item={true} xs={3}>
            <ReportOverview report={report} />
          </Grid>
          <Grid item={true} xs={3}>
            <ReportIdentity report={report} />
          </Grid>
          <Grid item={true} xs={6}>
            <EntityExternalReferences entityId={report.id} />
          </Grid>
        </Grid>
        <StixCoreObjectNotes entityId={report.id} />
        <Grid
          container={true}
          spacing={3}
          classes={{ container: classes.gridContainer }}
          style={{ marginTop: 15 }}
        >
          <Grid item={true} xs={6}>
            <EntityStixCoreRelationshipsDonut
              entityId={report.id}
              entityType="Stix-Observable"
              relationship_type="observable_refs"
              field="entity_type"
              height={150}
            />
          </Grid>
          <Grid item={true} xs={6}>
            <EntityStixCoreRelationshipsDonut
              entityId={report.id}
              entityType="Stix-Domain-Entity"
              relationship_type="object_refs"
              field="entity_type"
              height={150}
            />
          </Grid>
        </Grid>
        <Security needs={[KNOWLEDGE_KNUPDATE]}>
          <ReportEdition reportId={report.id} />
        </Security>
      </div>
    );
  }
}

ReportComponent.propTypes = {
  report: PropTypes.object,
  classes: PropTypes.object,
  t: PropTypes.func,
};

const Report = createFragmentContainer(ReportComponent, {
  report: graphql`
    fragment Report_report on Report {
      id
      ...ReportHeader_report
      ...ReportOverview_report
      ...ReportDetails_report
    }
  `,
});

export default compose(inject18n, withStyles(styles))(Report);
