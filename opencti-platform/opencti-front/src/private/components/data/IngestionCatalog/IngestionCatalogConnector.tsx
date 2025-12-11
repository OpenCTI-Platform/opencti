import { IngestionConnector } from '@components/data/IngestionCatalog';
import IngestionCatalogConnectorCreation from '@components/data/IngestionCatalog/IngestionCatalogConnectorCreation';
import IngestionCatalogConnectorHeader from '@components/data/IngestionCatalog/IngestionCatalogConnectorHeader';
import IngestionCatalogConnectorOverview from '@components/data/IngestionCatalog/IngestionCatalogConnectorOverview';
import { IngestionCatalogConnectorQuery } from '@components/data/IngestionCatalog/__generated__/IngestionCatalogConnectorQuery.graphql';
import useConnectorDeployDialog from '@components/data/IngestionCatalog/hooks/useConnectorDeployDialog';
import createDeploymentCountMap from '@components/data/IngestionCatalog/utils/createDeploymentCountMap';
import ConnectorDeploymentBanner from '@components/data/connectors/ConnectorDeploymentBanner';
import { ConnectorManagerStatusProvider, useConnectorManagerStatus } from '@components/data/connectors/ConnectorManagerStatusContext';
import { Stack } from '@mui/material';
import React, { Suspense, useEffect } from 'react';
import { graphql, PreloadedQuery, usePreloadedQuery } from 'react-relay';
import { useParams, useSearchParams } from 'react-router-dom';
import Breadcrumbs from '../../../../components/Breadcrumbs';
import ErrorNotFound from '../../../../components/ErrorNotFound';
import Loader, { LoaderVariant } from '../../../../components/Loader';
import { useFormatter } from '../../../../components/i18n';
import useConnectedDocumentModifier from '../../../../utils/hooks/useConnectedDocumentModifier';
import useEnterpriseEdition from '../../../../utils/hooks/useEnterpriseEdition';
import useQueryLoading from '../../../../utils/hooks/useQueryLoading';

const SEARCH_PARAMS = {
  OPEN_CONFIG: 'openConfig',
} as const;

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
  onClickDeploy: (connector: IngestionConnector, catalogId: string, hasActiveManagers: boolean, deploymentCount: number) => void;
  openConfig?: boolean;
}

const IngestionCatalogConnectorComponent = ({
  queryRef,
  onClickDeploy,
  openConfig,
}: IngestionCatalogConnectorComponentProps) => {
  const isEnterpriseEdition = useEnterpriseEdition();
  const { t_i18n } = useFormatter();
  const { setTitle } = useConnectedDocumentModifier();

  const { hasActiveManagers } = useConnectorManagerStatus();

  const { contract, connectors } = usePreloadedQuery(
    ingestionCatalogConnectorQuery,
    queryRef,
  );

  setTitle(t_i18n('Connector catalog | Ingestion | Data'));
  const connector = contract ? JSON.parse(contract.contract) : null;
  const deploymentCounts = createDeploymentCountMap(connectors);
  const deploymentCount = connector
    ? (deploymentCounts.get(connector.container_image) ?? 0)
    : 0;

  useEffect(() => {
    if (openConfig && contract && connector) {
      onClickDeploy(connector, contract.catalog_id, hasActiveManagers, deploymentCount);
    }
  }, [openConfig, contract]);

  if (!contract) return <ErrorNotFound />;

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
        <ConnectorDeploymentBanner hasActiveManagers={hasActiveManagers} />

        <Stack gap={4}>
          <IngestionCatalogConnectorHeader
            connector={connector}
            isEnterpriseEdition={isEnterpriseEdition}
            onClickDeploy={() => onClickDeploy(connector, contract?.catalog_id, hasActiveManagers, deploymentCount)}
          />
          <IngestionCatalogConnectorOverview connector={connector} />
        </Stack>
      </Stack>
    </>
  );
};

const IngestionCatalogConnector = () => {
  const { connectorSlug } = useParams();

  const [searchParams] = useSearchParams();
  const shouldAutoOpen = searchParams.get(SEARCH_PARAMS.OPEN_CONFIG) === 'true';

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
            openConfig={shouldAutoOpen}
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
            hasActiveManagers={catalogState.hasActiveManagers}
            onCreate={handleCreate}
            deploymentCount={catalogState.deploymentCount}
          />
        )
      }
    </Suspense>
  );
};

export default IngestionCatalogConnector;
