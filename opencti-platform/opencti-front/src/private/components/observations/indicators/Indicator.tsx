import { graphql } from 'relay-runtime';
import React from 'react';
import { useFragment } from 'react-relay';
import { Grid } from '@mui/material';
import { useInitCreateRelationshipContext } from '@components/common/stix_core_relationships/CreateRelationshipContextProvider';
import { Indicator_indicator$key } from './__generated__/Indicator_indicator.graphql';
import IndicatorDetails from './IndicatorDetails';
import StixDomainObjectOverview from '../../common/stix_domain_objects/StixDomainObjectOverview';
import SimpleStixObjectOrStixRelationshipStixCoreRelationships from '../../common/stix_core_relationships/SimpleStixObjectOrStixRelationshipStixCoreRelationships';
import StixCoreObjectOrStixRelationshipLastContainers from '../../common/containers/StixCoreObjectOrStixRelationshipLastContainers';
import StixCoreObjectExternalReferences from '../../analyses/external_references/StixCoreObjectExternalReferences';
import StixCoreObjectLatestHistory from '../../common/stix_core_objects/StixCoreObjectLatestHistory';
import StixCoreObjectOrStixCoreRelationshipNotes from '../../analyses/notes/StixCoreObjectOrStixCoreRelationshipNotes';
import ThreatPulseCard from '@components/common/threat_pulse/ThreatPulseCard';
import useOverviewLayoutCustomization from '../../../../utils/hooks/useOverviewLayoutCustomization';

const indicatorFragment = graphql`
  fragment Indicator_indicator on Indicator {
    id
    standard_id
    entity_type
    x_opencti_stix_ids
    x_opencti_reliability
    spec_version
    revoked
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
    name
    pattern_type
    status {
      id
      order
      template {
        name
        color
      }
    }
    workflowEnabled
    ...IndicatorDetails_indicator
  }
`;

interface IndicatorProps {
  indicatorData: Indicator_indicator$key;
}

const Indicator: React.FC<IndicatorProps> = ({
  indicatorData,
}) => {
  useInitCreateRelationshipContext();

  const indicator = useFragment<Indicator_indicator$key>(
    indicatorFragment,
    indicatorData,
  );
  const overviewLayoutCustomization = useOverviewLayoutCustomization(indicator.entity_type);
  return (
    <div data-testid="indicator-overview">
      <Grid
        container={true}
        spacing={3}
        style={{ marginBottom: 20 }}
      >
        {
          overviewLayoutCustomization.map(({ key, width }) => {
            switch (key) {
              case 'details':
                return (
                  <Grid key={key} item xs={width}>
                    <IndicatorDetails indicator={indicator} />
                  </Grid>
                );
              case 'basicInformation':
                return (
                  <Grid key={key} item xs={width}>
                    <StixDomainObjectOverview
                      stixDomainObject={indicator}
                      withPattern={true}
                    />
                  </Grid>
                );
              case 'threatPulse':
                return (
                  <Grid key={key} item xs={width}>
                    <ThreatPulseCard entityId={indicator.id} />
                  </Grid>
                );
              case 'latestCreatedRelationships':
                return (
                  <Grid key={key} item xs={width}>
                    <SimpleStixObjectOrStixRelationshipStixCoreRelationships
                      stixObjectOrStixRelationshipId={indicator.id}
                      stixObjectOrStixRelationshipLink={`/dashboard/observations/indicators/${indicator.id}/knowledge`}
                    />
                  </Grid>
                );
              case 'latestContainers':
                return (
                  <Grid key={key} item xs={width}>
                    <StixCoreObjectOrStixRelationshipLastContainers
                      stixCoreObjectOrStixRelationshipId={indicator.id}
                    />
                  </Grid>
                );
              case 'externalReferences':
                return (
                  <Grid key={key} item xs={width}>
                    <StixCoreObjectExternalReferences stixCoreObjectId={indicator.id} />
                  </Grid>
                );
              case 'mostRecentHistory':
                return (
                  <Grid key={key} item xs={width}>
                    <StixCoreObjectLatestHistory stixCoreObjectId={indicator.id} />
                  </Grid>
                );
              case 'notes':
                return (
                  <Grid key={key} item xs={width}>
                    <StixCoreObjectOrStixCoreRelationshipNotes
                      stixCoreObjectOrStixCoreRelationshipId={indicator.id}
                      defaultMarkings={indicator.objectMarking ?? []}
                    />
                  </Grid>
                );
              default:
                return null;
            }
          })
        }
      </Grid>
    </div>
  );
};

export default Indicator;
