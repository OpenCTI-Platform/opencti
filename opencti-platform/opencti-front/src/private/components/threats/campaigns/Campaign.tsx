import React from 'react';
import { graphql, useFragment } from 'react-relay';
import Grid from '@mui/material/Grid';
import { makeStyles } from '@mui/styles';
import CampaignDetails from './CampaignDetails';
import CampaignEdition from './CampaignEdition';
import CampaignPopover from './CampaignPopover';
import StixCoreObjectOrStixCoreRelationshipLastReports
  from '../../analysis/reports/StixCoreObjectOrStixCoreRelationshipLastReports';
import StixDomainObjectHeader from '../../common/stix_domain_objects/StixDomainObjectHeader';
import Security from '../../../../utils/Security';
import { KNOWLEDGE_KNUPDATE } from '../../../../utils/hooks/useGranted';
import StixCoreObjectOrStixCoreRelationshipNotes from '../../analysis/notes/StixCoreObjectOrStixCoreRelationshipNotes';
import StixDomainObjectOverview from '../../common/stix_domain_objects/StixDomainObjectOverview';
import StixCoreObjectExternalReferences from '../../analysis/external_references/StixCoreObjectExternalReferences';
import StixCoreObjectLatestHistory from '../../common/stix_core_objects/StixCoreObjectLatestHistory';
import SimpleStixObjectOrStixRelationshipStixCoreRelationships
  from '../../common/stix_core_relationships/SimpleStixObjectOrStixRelationshipStixCoreRelationships';
import { Campaign_campaign$key } from './__generated__/Campaign_campaign.graphql';

const useStyles = makeStyles(() => ({
  container: {
    margin: 0,
  },
  gridContainer: {
    marginBottom: 20,
  },
}));

const campaignFragment = graphql`
    fragment Campaign_campaign on Campaign {
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
            }
        }
        creators {
            id
            name
        }
        objectMarking {
            edges {
                node {
                    id
                    definition_type
                    definition
                    x_opencti_order
                    x_opencti_color
                }
            }
        }
        objectLabel {
            edges {
                node {
                    id
                    value
                    color
                }
            }
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
        ...CampaignDetails_campaign
    }
`;

const CampaignComponent = ({ campaign }: { campaign: Campaign_campaign$key }) => {
  const campaignData = useFragment(campaignFragment, campaign);
  const classes = useStyles();

  return (
    <div className={classes.container}>
      <StixDomainObjectHeader
        entityType={'Campaign'}
        stixDomainObject={campaignData}
        PopoverComponent={<CampaignPopover />}
        enableQuickSubscription
      />
      <Grid
        container={true}
        spacing={3}
        classes={{ container: classes.gridContainer }}
      >
        <Grid item={true} xs={6} style={{ paddingTop: 10 }}>
          <CampaignDetails campaign={campaignData} />
        </Grid>
        <Grid item={true} xs={6} style={{ paddingTop: 10 }}>
          <StixDomainObjectOverview stixDomainObject={campaignData} />
        </Grid>
      </Grid>
      <Grid
        container={true}
        spacing={3}
        classes={{ container: classes.gridContainer }}
        style={{ marginTop: 25 }}
      >
        <Grid item={true} xs={6}>
          <SimpleStixObjectOrStixRelationshipStixCoreRelationships
            stixObjectOrStixRelationshipId={campaignData.id}
            stixObjectOrStixRelationshipLink={`/dashboard/threats/campaigns/${campaignData.id}/knowledge`}
          />
        </Grid>
        <Grid item={true} xs={6}>
          <StixCoreObjectOrStixCoreRelationshipLastReports
            stixCoreObjectOrStixCoreRelationshipId={campaignData.id}
          />
        </Grid>
      </Grid>
      <Grid
        container={true}
        spacing={3}
        classes={{ container: classes.gridContainer }}
        style={{ marginTop: 25 }}
      >
        <Grid item={true} xs={6}>
          <StixCoreObjectExternalReferences stixCoreObjectId={campaignData.id} />
        </Grid>
        <Grid item={true} xs={6}>
          <StixCoreObjectLatestHistory stixCoreObjectId={campaignData.id} />
        </Grid>
      </Grid>
      <StixCoreObjectOrStixCoreRelationshipNotes
        stixCoreObjectOrStixCoreRelationshipId={campaignData.id}
        defaultMarkings={(campaignData.objectMarking?.edges ?? []).map(
          (edge) => edge.node,
        )}
      />
      <Security needs={[KNOWLEDGE_KNUPDATE]}>
        <CampaignEdition campaignId={campaignData.id} />
      </Security>
    </div>
  );
};

export default CampaignComponent;
