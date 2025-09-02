import { useNavigate, useParams } from 'react-router-dom';
import { graphql, PreloadedQuery, usePreloadedQuery } from 'react-relay';
import React, { Suspense, useState } from 'react';
import IngestionCatalogConnectorHeader from '@components/data/IngestionCatalog/IngestionCatalogConnectorHeader';
import IngestionCatalogConnectorOverview from '@components/data/IngestionCatalog/IngestionCatalogConnectorOverview';
import { IngestionCatalogConnectorQuery } from '@components/data/IngestionCatalog/__generated__/IngestionCatalogConnectorQuery.graphql';
import { ConnectorManagerStatusProvider, useConnectorManagerStatus } from '@components/data/connectors/ConnectorManagerStatusContext';
import NoConnectorManagersBanner from '@components/data/connectors/NoConnectorManagersBanner';
import { Stack } from '@mui/material';
import IngestionCatalogConnectorCreation from '@components/data/IngestionCatalog/IngestionCatalogConnectorCreation';
import { IngestionConnector } from '@components/data/IngestionCatalog';
import Breadcrumbs from '../../../../components/Breadcrumbs';
import Loader, { LoaderVariant } from '../../../../components/Loader';
import useQueryLoading from '../../../../utils/hooks/useQueryLoading';
import { useFormatter } from '../../../../components/i18n';
import useConnectedDocumentModifier from '../../../../utils/hooks/useConnectedDocumentModifier';
import ErrorNotFound from '../../../../components/ErrorNotFound';
import useEnterpriseEdition from '../../../../utils/hooks/useEnterpriseEdition';
import { resolveLink } from '../../../../utils/Entity';

const ingestionCatalogConnectorQuery = graphql`
  query IngestionCatalogConnectorQuery($slug: String!) {
    contract(slug: $slug) {
      catalog_id
      contract
    }
  }
`;

interface IngestionCatalogConnectorComponentProps {
  queryRef: PreloadedQuery<IngestionCatalogConnectorQuery>;
  onClickDeploy: (connector: IngestionConnector, catalogId: string, hasRegisteredManagers: boolean) => void;
}

const IngestionCatalogConnectorComponent = ({
  queryRef,
  onClickDeploy,
}: IngestionCatalogConnectorComponentProps) => {
  const isEnterpriseEdition = useEnterpriseEdition();
  const { t_i18n } = useFormatter();
  const { setTitle } = useConnectedDocumentModifier();

  const { hasRegisteredManagers } = useConnectorManagerStatus();

  const { contract } = usePreloadedQuery(
    ingestionCatalogConnectorQuery,
    queryRef,
  );

  setTitle(t_i18n('Connector catalog | Ingestion | Data'));

  if (!contract) return <ErrorNotFound />;

  const connector = JSON.parse(contract.contract);

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
        { !hasRegisteredManagers && <NoConnectorManagersBanner />}

        <IngestionCatalogConnectorHeader
          connector={connector}
          isEnterpriseEdition={isEnterpriseEdition}
          onClickDeploy={() => onClickDeploy(connector, contract?.catalog_id, hasRegisteredManagers)}
        />

        <IngestionCatalogConnectorOverview connector={connector} />
      </Stack>
    </>
  );
};

interface CatalogState {
  selectedConnector: IngestionConnector | null;
  selectedCatalogId: string;
  hasRegisteredManagers: boolean;
}

const IngestionCatalogConnector = () => {
  const navigate = useNavigate();

  const { connectorSlug } = useParams();

  const queryRef = useQueryLoading<IngestionCatalogConnectorQuery>(
    ingestionCatalogConnectorQuery,
    { slug: connectorSlug ?? '' },
  );

  const [catalogState, setCatalogState] = useState<CatalogState>({
    selectedConnector: null,
    selectedCatalogId: '',
    hasRegisteredManagers: false,
  });

  const handleOpenDeployDialog = (connector: IngestionConnector, catalogId: string, registeredManagers: boolean) => {
    setCatalogState((prev) => ({
      ...prev,
      selectedConnector: connector,
      selectedCatalogId: catalogId,
      hasRegisteredManagers: registeredManagers,
    }));
  };

  const handleCloseDeployDialog = () => {
    setCatalogState((prev) => ({
      ...prev,
      selectedConnector: null,
      selectedCatalogId: '',
    }));
  };

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
            onCreate={(connectorId) => {
              navigate(`${resolveLink('Connectors')}/${connectorId}`);
            }}
          />
        )
      }
    </Suspense>
  );
};

export default IngestionCatalogConnector;
