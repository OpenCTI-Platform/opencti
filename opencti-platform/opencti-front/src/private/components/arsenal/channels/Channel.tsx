import React from 'react';
import { graphql, useFragment } from 'react-relay';
import Grid from '@mui/material/Grid';
import { Channel_channel$key } from '@components/arsenal/channels/__generated__/Channel_channel.graphql';
import ChannelDetails from './ChannelDetails';
import ChannelEdition from './ChannelEdition';
import Security from '../../../../utils/Security';
import { KNOWLEDGE_KNUPDATE } from '../../../../utils/hooks/useGranted';
import StixCoreObjectOrStixCoreRelationshipNotes from '../../analyses/notes/StixCoreObjectOrStixCoreRelationshipNotes';
import StixDomainObjectOverview from '../../common/stix_domain_objects/StixDomainObjectOverview';
import StixCoreObjectExternalReferences from '../../analyses/external_references/StixCoreObjectExternalReferences';
import StixCoreObjectLatestHistory from '../../common/stix_core_objects/StixCoreObjectLatestHistory';
import SimpleStixObjectOrStixRelationshipStixCoreRelationships from '../../common/stix_core_relationships/SimpleStixObjectOrStixRelationshipStixCoreRelationships';
import StixCoreObjectOrStixRelationshipLastContainers from '../../common/containers/StixCoreObjectOrStixRelationshipLastContainers';
import useOverviewLayoutCustomization from '../../../../utils/hooks/useOverviewLayoutCustomization';

export const channelFragment = graphql`
  fragment Channel_channel on Channel {
    id
    standard_id
    entity_type
    x_opencti_stix_ids
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
    aliases
    status {
      id
      order
      template {
        name
        color
      }
    }
    workflowEnabled
    ...ChannelDetails_channel
  }
`;

interface ChannelProps {
  channelData: Channel_channel$key
}

const Channel: React.FC<ChannelProps> = ({ channelData }) => {
  const channel = useFragment<Channel_channel$key>(channelFragment, channelData);
  const overviewLayoutCustomization = useOverviewLayoutCustomization(channel.entity_type);

  return (
    <>
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
                    <ChannelDetails channel={channel} />
                  </Grid>
                );
              case 'basicInformation':
                return (
                  <Grid key={key} item xs={width}>
                    <StixDomainObjectOverview stixDomainObject={channel} />
                  </Grid>
                );
              case 'latestCreatedRelationships':
                return (
                  <Grid key={key} item xs={width}>
                    <SimpleStixObjectOrStixRelationshipStixCoreRelationships
                      stixObjectOrStixRelationshipId={channel.id}
                      stixObjectOrStixRelationshipLink={`/dashboard/arsenal/channels/${channel.id}/knowledge`}
                    />
                  </Grid>
                );
              case 'latestContainers':
                return (
                  <Grid key={key} item xs={width}>
                    <StixCoreObjectOrStixRelationshipLastContainers
                      stixCoreObjectOrStixRelationshipId={channel.id}
                    />
                  </Grid>
                );
              case 'externalReferences':
                return (
                  <Grid key={key} item xs={width}>
                    <StixCoreObjectExternalReferences
                      stixCoreObjectId={channel.id}
                    />
                  </Grid>
                );
              case 'mostRecentHistory':
                return (
                  <Grid key={key} item xs={width}>
                    <StixCoreObjectLatestHistory
                      stixCoreObjectId={channel.id}
                    />
                  </Grid>
                );
              case 'notes':
                return (
                  <Grid key={key} item xs={width}>
                    <StixCoreObjectOrStixCoreRelationshipNotes
                      stixCoreObjectOrStixCoreRelationshipId={channel.id}
                      defaultMarkings={channel.objectMarking ?? []}
                    />
                  </Grid>
                );
              default:
                return null;
            }
          })
        }
      </Grid>
      <Security needs={[KNOWLEDGE_KNUPDATE]}>
        <ChannelEdition channelId={channel.id} />
      </Security>
    </>
  );
};

export default Channel;
