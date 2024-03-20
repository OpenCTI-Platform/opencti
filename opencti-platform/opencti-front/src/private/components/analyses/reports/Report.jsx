import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import { graphql, createFragmentContainer } from 'react-relay';
import withStyles from '@mui/styles/withStyles';
import Grid from '@mui/material/Grid';
import ReportDetails from './ReportDetails';
import ReportEdition from './ReportEdition';
import StixDomainObjectOverview from '../../common/stix_domain_objects/StixDomainObjectOverview';
import StixCoreObjectExternalReferences from '../external_references/StixCoreObjectExternalReferences';
import { KnowledgeSecurity } from '../../../../utils/Security';
import { KNOWLEDGE_KNUPDATE } from '../../../../utils/hooks/useGranted';
import StixCoreObjectOrStixCoreRelationshipNotes from '../notes/StixCoreObjectOrStixCoreRelationshipNotes';
import StixCoreObjectLatestHistory from '../../common/stix_core_objects/StixCoreObjectLatestHistory';

const styles = () => ({
  gridContainer: {
    marginBottom: 20,
  },
});

class ReportComponent extends Component {
  render() {
    const { classes, report } = this.props;
    return (
      <>
        <Grid
          container={true}
          spacing={3}
          classes={{ container: classes.gridContainer }}
        >
          <Grid item={true} xs={6} style={{ paddingTop: 10 }}>
            <ReportDetails report={report} />
          </Grid>
          <Grid item={true} xs={6} style={{ paddingTop: 10 }}>
            <StixDomainObjectOverview
              stixDomainObject={report}
              displayAssignees
              displayParticipants
            />
          </Grid>
          <Grid item={true} xs={6} style={{ marginTop: 30 }}>
            <StixCoreObjectExternalReferences stixCoreObjectId={report.id} />
          </Grid>
          <Grid item={true} xs={6} style={{ marginTop: 30 }}>
            <StixCoreObjectLatestHistory stixCoreObjectId={report.id} />
          </Grid>
        </Grid>
        <StixCoreObjectOrStixCoreRelationshipNotes
          stixCoreObjectOrStixCoreRelationshipId={report.id}
          defaultMarkings={report.objectMarking ?? []}
        />
        <KnowledgeSecurity needs={[KNOWLEDGE_KNUPDATE]} entity='Report'>
          <ReportEdition reportId={report.id} />
        </KnowledgeSecurity>
      </>
    );
  }
}

ReportComponent.propTypes = {
  report: PropTypes.object,
  classes: PropTypes.object,
};

const Report = createFragmentContainer(ReportComponent, {
  report: graphql`
    fragment Report_report on Report {
      id
      standard_id
      entity_type
      x_opencti_stix_ids
      spec_version
      revoked
      x_opencti_reliability
      confidence
      created
      modified
      created_at
      updated_at
      createdBy {
        ... on Identity {
          id
          name
          entity_type
          x_opencti_reliability
        }
      }
      creators {
        id
        name
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
      objectAssignee {
        id
        name
        entity_type
      }
      objectParticipant {
        id
        name
        entity_type
      }
      status {
        id
        order
        template {
          name
          color
        }
      }
      workflowEnabled
      ...ReportDetails_report
      ...ContainerHeader_container
    }
  `,
});

export default withStyles(styles)(Report);
