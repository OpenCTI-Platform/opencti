import { useParams } from 'react-router-dom';
import { graphql, PreloadedQuery, usePreloadedQuery } from 'react-relay';
import React, { Suspense } from 'react';
import IngestionCatalogConnectorHeader from '@components/data/IngestionCatalog/IngestionCatalogConnectorHeader';
import IngestionCatalogConnectorOverview from '@components/data/IngestionCatalog/IngestionCatalogConnectorOverview';
import { IngestionCatalogConnectorQuery } from '@components/data/IngestionCatalog/__generated__/IngestionCatalogConnectorQuery.graphql';
import { ConnectorManagerStatusProvider, useConnectorManagerStatus } from '@components/data/connectors/ConnectorManagerStatusContext';
import ConnectorDeploymentBanner from '@components/data/connectors/ConnectorDeploymentBanner';
import { Stack } from '@mui/material';
import IngestionCatalogConnectorCreation from '@components/data/IngestionCatalog/IngestionCatalogConnectorCreation';
import { IngestionConnector } from '@components/data/IngestionCatalog';
import createDeploymentCountMap from '@components/data/IngestionCatalog/utils/createDeploymentCountMap';
import useConnectorDeployDialog from '@components/data/IngestionCatalog/hooks/useConnectorDeployDialog';
import Breadcrumbs from '../../../../components/Breadcrumbs';
import Loader, { LoaderVariant } from '../../../../components/Loader';
import useQueryLoading from '../../../../utils/hooks/useQueryLoading';
import { useFormatter } from '../../../../components/i18n';
import useConnectedDocumentModifier from '../../../../utils/hooks/useConnectedDocumentModifier';
import ErrorNotFound from '../../../../components/ErrorNotFound';
import useEnterpriseEdition from '../../../../utils/hooks/useEnterpriseEdition';

const ingestionCatalogConnectorQuery = graphql`
  query IngestionCatalogConnectorQuery($slug: String!) {
    contract(slug: $slug) {
      catalog_id
      contract
    }
    connectors {
      manager_contract_image
    }
  }
`;

interface IngestionCatalogConnectorComponentProps {
  queryRef: PreloadedQuery<IngestionCatalogConnectorQuery>;
  onClickDeploy: (connector: IngestionConnector, catalogId: string, hasRegisteredManagers: boolean, deploymentCount: number) => void;
}

const IngestionCatalogConnectorComponent = ({
  queryRef,
  onClickDeploy,
}: IngestionCatalogConnectorComponentProps) => {
  const isEnterpriseEdition = useEnterpriseEdition();
  const { t_i18n } = useFormatter();
  const { setTitle } = useConnectedDocumentModifier();

  const { hasRegisteredManagers } = useConnectorManagerStatus();

  const { contract, connectors } = usePreloadedQuery(
    ingestionCatalogConnectorQuery,
    queryRef,
  );

  setTitle(t_i18n('Connector catalog | Ingestion | Data'));

  if (!contract) return <ErrorNotFound />;

  const connector = JSON.parse(contract.contract);

  const deploymentCounts = createDeploymentCountMap(connectors);
  const deploymentCount = deploymentCounts.get(connector.container_image) ?? 0;

  return (
    <>
      <Breadcrumbs
        elements={[
          { label: t_i18n('Data') },
          { label: t_i18n('Ingestion') },
          { label: t_i18n('Connector catalog'), link: '/dashboard/data/ingestion/catalog' },
          { label: connector.title, current: true },
        ]}
      />

      <Stack gap={2}>
        <ConnectorDeploymentBanner hasRegisteredManagers={hasRegisteredManagers} />

        <IngestionCatalogConnectorHeader
          connector={connector}
          isEnterpriseEdition={isEnterpriseEdition}
          onClickDeploy={() => onClickDeploy(connector, contract?.catalog_id, hasRegisteredManagers, deploymentCount)}
        />

        <IngestionCatalogConnectorOverview connector={connector} />
      </Stack>
    </>
  );
};

const IngestionCatalogConnector = () => {
  const { connectorSlug } = useParams();

  const queryRef = useQueryLoading<IngestionCatalogConnectorQuery>(
    ingestionCatalogConnectorQuery,
    { slug: connectorSlug ?? '' },
  );

  const { catalogState, handleOpenDeployDialog, handleCloseDeployDialog, handleCreate } = useConnectorDeployDialog();

  return (
    <Suspense fallback={<Loader variant={LoaderVariant.container} />}>
      {queryRef && (
        <ConnectorManagerStatusProvider>
          <IngestionCatalogConnectorComponent
            queryRef={queryRef}
            onClickDeploy={handleOpenDeployDialog}
          />
        </ConnectorManagerStatusProvider>
      )}

      {
        catalogState.selectedConnector && (
          <IngestionCatalogConnectorCreation
            open={!!catalogState.selectedConnector}
            connector={catalogState.selectedConnector}
            onClose={handleCloseDeployDialog}
            catalogId={catalogState.selectedCatalogId}
            hasRegisteredManagers={catalogState.hasRegisteredManagers}
            onCreate={handleCreate}
            deploymentCount={catalogState.deploymentCount}
          />
        )
      }
    </Suspense>
  );
};

export default IngestionCatalogConnector;
