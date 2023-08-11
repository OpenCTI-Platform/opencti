import { makeStyles } from '@mui/styles';
import { graphql, useFragment } from 'react-relay';
import { Grid } from '@mui/material';
import StixDomainObjectHeader from '../../common/stix_domain_objects/StixDomainObjectHeader';
import StixDomainObjectOverview from '../../common/stix_domain_objects/StixDomainObjectOverview';
import SimpleStixObjectOrStixRelationshipStixCoreRelationships from '../../common/stix_core_relationships/SimpleStixObjectOrStixRelationshipStixCoreRelationships';
import StixCoreObjectExternalReferences from '../../analyses/external_references/StixCoreObjectExternalReferences';
import StixCoreObjectLatestHistory from '../../common/stix_core_objects/StixCoreObjectLatestHistory';
import StixCoreObjectOrStixCoreRelationshipNotes from '../../analyses/notes/StixCoreObjectOrStixCoreRelationshipNotes';
import { Asset_financialAsset$key } from './__generated__/Asset_financialAsset.graphql';
import AssetPopover from './AssetPopover';
import AssetDetails from './AssetDetails';
import AssetEdition from './AssetEdition';
import { KNOWLEDGE_KNUPDATE } from '../../../../utils/hooks/useGranted';
import Security from '../../../../utils/Security';
import StixCoreObjectOrStixRelationshipLastContainers from '../../common/containers/StixCoreObjectOrStixRelationshipLastContainers';

const useStyles = makeStyles(() => ({
  container: {
    margin: 0,
  },
  gridContainer: {
    marginBottom: 20,
  },
}));

const assetFragment = graphql`
  fragment Asset_financialAsset on FinancialAsset {
    id
    standard_id
    entity_type
    # StixObject
    spec_version
    created_at
    updated_at
    # StixDomainObject
    revoked
    created
    modified
    # StixCoreObject
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
    # Financial Asset
    name: name
    asset_type
    asset_value
    currency_code
  }
`;

const AssetComponent = ({ assetData }: { assetData: Asset_financialAsset$key }) => {
  const classes = useStyles();
  const asset = useFragment<Asset_financialAsset$key>(assetFragment, assetData);
  return (
    <div className={classes.container}>
      <StixDomainObjectHeader
        entityType={'Financial-Asset'}
        disableSharing={true}
        stixDomainObject={asset}
        isOpenctiAlias={false}
        PopoverComponent={<AssetPopover id={asset.id} />}
      />
      <Grid
        container={true}
        spacing={3}
        classes={{ container: classes.gridContainer }}
      >
        <Grid item={true} xs={6} style={{ paddingTop: 10 }}>
          <AssetDetails asset={asset} />
        </Grid>
        <Grid item={true} xs={6} style={{ paddingTop: 10 }}>
          <StixDomainObjectOverview stixDomainObject={asset} />
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
            stixObjectOrStixRelationshipId={asset.id}
            stixObjectOrStixRelationshipLink={`/dashboard/financial/assets/${asset.id}/knowledge`}
          />
        </Grid>
        <Grid item={true} xs={6}>
          <StixCoreObjectOrStixRelationshipLastContainers
            authorId={asset.id}
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
          <StixCoreObjectExternalReferences
            stixCoreObjectId={asset.id}
          />
        </Grid>
        <Grid item={true} xs={6}>
          <StixCoreObjectLatestHistory
            stixCoreObjectId={asset.id}
          />
        </Grid>
      </Grid>
      <StixCoreObjectOrStixCoreRelationshipNotes
        stixCoreObjectOrStixCoreRelationshipId={asset.id}
        defaultMarkings={(asset.objectMarking?.edges ?? []).map((edge) => edge.node)}
      />
      <Security needs={[KNOWLEDGE_KNUPDATE]}>
        <AssetEdition assetId={asset.id} />
      </Security>
    </div>
  );
};

export default AssetComponent;
