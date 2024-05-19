import { Grid, styled } from '@mui/material';
import React, { FunctionComponent } from 'react';
import useHelper from 'src/utils/hooks/useHelper';
import Security from 'src/utils/Security';
import { KNOWLEDGE_KNUPDATE } from 'src/utils/hooks/useGranted';
import StixDomainObjectOverview from '@components/common/stix_domain_objects/StixDomainObjectOverview';
import StixCoreObjectLatestHistory from '@components/common/stix_core_objects/StixCoreObjectLatestHistory';
import { graphql, useFragment } from 'react-relay';
import ReportEdition from './ReportEdition';
import ReportDetails from './ReportDetails';
import StixCoreObjectExternalReferences from '../external_references/StixCoreObjectExternalReferences';
import StixCoreObjectOrStixCoreRelationshipNotes from '../notes/StixCoreObjectOrStixCoreRelationshipNotes';
import { Report_report$key } from './__generated__/Report_report.graphql';

const ReportComponentFragment = graphql`
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
`;

interface ReportComponentProps {
  reportFragment: Report_report$key;
}

const ReportComponent: FunctionComponent<ReportComponentProps> = ({
  reportFragment,
}) => {
  const report = useFragment<Report_report$key>(
    ReportComponentFragment,
    reportFragment,
  );
  const { isFeatureEnable } = useHelper();
  const FABReplaced = isFeatureEnable('FAB_REPLACEMENT');

  // Styled components
  const ParentGrid = styled(Grid)({
    marginBottom: 20,
  });
  const PaddedGrid = styled(Grid)({
    paddingTop: 10,
  });
  const MarginGrid = styled(Grid)({
    marginTop: 30,
  });

  return (<>
    <ParentGrid
      container={true}
      spacing={3}
    >
      <PaddedGrid item={true} xs={6}>
        <ReportDetails report={report} />
      </PaddedGrid>
      <PaddedGrid item={true} xs={6}>
        <StixDomainObjectOverview
          stixDomainObject={report}
          displayAssignees
          displayParticipants
        />
      </PaddedGrid>
      <MarginGrid item={true} xs={6}>
        <StixCoreObjectExternalReferences stixCoreObjectId={report.id} />
      </MarginGrid>
      <MarginGrid item={true} xs={6}>
        <StixCoreObjectLatestHistory stixCoreObjectId={report.id} />
      </MarginGrid>
    </ParentGrid>
    <StixCoreObjectOrStixCoreRelationshipNotes
      stixCoreObjectOrStixCoreRelationshipId={report.id}
      defaultMarkings={report.objectMarking ?? []}
    />
    {!FABReplaced
      && <Security needs={[KNOWLEDGE_KNUPDATE]}>
        <ReportEdition reportId={report.id} />
      </Security>
    }
  </>);
};

export default ReportComponent;
