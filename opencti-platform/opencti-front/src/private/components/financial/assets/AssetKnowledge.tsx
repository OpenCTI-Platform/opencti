// eslint-disable-next-line @typescript-eslint/ban-ts-comment
// @ts-nocheck
import { makeStyles } from '@mui/styles';
import { graphql, useFragment } from 'react-relay';
import { Route, Switch } from 'react-router-dom';
import { AssetKnowledge_financialAsset$key } from './__generated__/AssetKnowledge_financialAsset.graphql';
import StixDomainObjectHeader from '../../common/stix_domain_objects/StixDomainObjectHeader';
import AssetPopover from './AssetPopover';
import StixDomainObjectKnowledge from '../../common/stix_domain_objects/StixDomainObjectKnowledge';
import EntityStixCoreRelationships from '../../common/stix_core_relationships/EntityStixCoreRelationships';

const useStyles = makeStyles(() => ({
  container: {
    margin: 0,
    padding: '0 200px 0 0',
  },
}));

const assetKnowledgeFragment = graphql`
  fragment AssetKnowledge_financialAsset on FinancialAsset {
    id
    name: name
  }
`;

const AssetKnowledgeComponent = ({
  assetData,
}: {
  assetData: AssetKnowledge_financialAsset$key;
}) => {
  const classes = useStyles();
  const asset = useFragment<AssetKnowledge_financialAsset$key>(
    assetKnowledgeFragment,
    assetData,
  );
  const link = `/dashboard/financial/assets/${asset.id}/knowledge`;
  return (
    <div className={classes.container}>
      <StixDomainObjectHeader
        entityType={'Financial-Asset'}
        disableSharing={true}
        stixDomainObject={asset}
        PopoverComponent={<AssetPopover id={asset.id} />}
      />
      <Switch>
        <Route
          exact
          path="/dashboard/financial/assets/:assetId/knowledge/overview"
          render={(routeProps) => (
            <StixDomainObjectKnowledge
              stixDomainObjectId={asset.id}
              stixDomainObjectType="Financial-Asset"
              {...routeProps}
            />
          )}
        />
        <Route
          exact
          path="/dashboard/financial/assets/:assetId/knowledge/organizations"
          render={(routeProps) => (
            <EntityStixCoreRelationships
              entityId={asset.id}
              relationshipTypes={['belongs-to', 'owns']}
              stixCoreObjectTypes={['Organization']}
              entityLink={link}
              isRelationReversed={true}
              {...routeProps}
            />
          )}
        />
        <Route
          exact
          path="/dashboard/financial/assets/:assetId/knowledge/individuals"
          render={(routeProps) => (
            <EntityStixCoreRelationships
              entityId={asset.id}
              relationshipTypes={['owns']}
              stixCoreObjectTypes={['Individual']}
              entityLink={link}
              isRelationReversed={true}
              {...routeProps}
            />
          )}
        />
        <Route
          exact
          path="/dashboard/financial/assets/:assetId/knowledge/locations"
          render={(routeProps) => (
            <EntityStixCoreRelationships
              entityId={asset.id}
              relationshipTypes={['located-at']}
              stixCoreObjectTypes={['Location']}
              entityLink={link}
              isRelationReversed={false}
              {...routeProps}
            />
          )}
        />
        <Route
          exact
          path="/dashboard/financial/assets/:accountId/knowledge/threat_actors"
          render={(routeProps) => (
            <EntityStixCoreRelationships
              entityId={asset.id}
              relationshipTypes={['owns']}
              stixCoreObjectTypes={['Threat-Actor']}
              entityLink={link}
              isRelationReversed={true}
              {...routeProps}
            />
          )}
        />
        <Route
          exact
          path="/dashboard/financial/assets/:assetId/knowledge/related"
          render={(routeProps) => (
            <EntityStixCoreRelationships
              entityId={asset.id}
              relationshipTypes={['related-to']}
              stixCoreObjectTypes={[
                'Threat-Actor',
                'Individual',
                'Organization',
              ]}
              entityLink={link}
              allDirections={true}
              {...routeProps}
            />
          )}
        />
      </Switch>
    </div>
  );
};

export default AssetKnowledgeComponent;
