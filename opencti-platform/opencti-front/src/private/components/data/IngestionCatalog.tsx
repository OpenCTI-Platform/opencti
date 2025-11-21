import React, { Suspense, useEffect } from 'react';
import IngestionMenu from '@components/data/IngestionMenu';
import { useQueryLoader } from 'react-relay';
import IngestionCatalogCard from '@components/data/IngestionCatalog/IngestionCatalogCard';
import useIngestionCatalogFilters from '@components/data/IngestionCatalog/hooks/useIngestionCatalogFilters';
import { useSearchParams } from 'react-router-dom';
import { Stack } from '@mui/material';
import { Search } from '@mui/icons-material';
import Grid from '@mui/material/Grid2';
import { ConnectorManagerStatusProvider, useConnectorManagerStatus } from '@components/data/connectors/ConnectorManagerStatusContext';
import ConnectorDeploymentBanner from '@components/data/connectors/ConnectorDeploymentBanner';
import IngestionCatalogConnectorCreation from '@components/data/IngestionCatalog/IngestionCatalogConnectorCreation';
import { IngestionConnectorType } from '@components/data/IngestionCatalog/utils/ingestionConnectorTypeMetadata';
import createDeploymentCountMap from '@components/data/IngestionCatalog/utils/createDeploymentCountMap';
import useConnectorDeployDialog from '@components/data/IngestionCatalog/hooks/useConnectorDeployDialog';
import { IngestionConnectorsCatalogsQuery } from '@components/data/IngestionCatalog/__generated__/IngestionConnectorsCatalogsQuery.graphql';
import IngestionConnectorsCatalogs, { ingestionConnectorsCatalogsQuery } from '@components/data/IngestionCatalog/IngestionConnectorsCatalog';
import { IngestionConnectorsQuery } from '@components/data/IngestionCatalog/__generated__/IngestionConnectorsQuery.graphql';
import IngestionConnectors, { ingestionConnectorsQuery } from '@components/data/IngestionCatalog/IngestionConnectors';
import Breadcrumbs from '../../../components/Breadcrumbs';
import { useFormatter } from '../../../components/i18n';
import useConnectedDocumentModifier from '../../../utils/hooks/useConnectedDocumentModifier';
import PageContainer from '../../../components/PageContainer';
import Loader, { LoaderVariant } from '../../../components/Loader';
import GradientButton from '../../../components/GradientButton';
import IngestionCatalogFilters from './IngestionCatalog/IngestionCatalogFilters';
import GradientCard from '../../../components/GradientCard';
import { MESSAGING$ } from '../../../relay/environment';
import useEnterpriseEdition from '../../../utils/hooks/useEnterpriseEdition';

interface IngestionCatalogComponentProps {
  catalogsData: IngestionConnectorsCatalogsQuery['response'];
  deploymentData: IngestionConnectorsQuery['response'];
  onClickDeploy: (connector: IngestionConnector, catalogId: string, hasActiveManagers: boolean, deploymentCount: number) => void;
}

type IngestionTypeMap = {
  string: string;
  integer: number;
  dict: object;
  array: string[];
  boolean: boolean;
};

export type IngestionTypedProperty<K extends keyof IngestionTypeMap = keyof IngestionTypeMap> = {
  type: K;
  default: IngestionTypeMap[K];
  description: string;
  format?: string;
};

export interface IngestionConnector {
  title: string,
  slug: string,
  description: string,
  short_description: string,
  logo: string,
  use_cases: string[],
  verified: boolean,
  last_verified_date: string,
  playbook_supported: boolean,
  max_confidence_level: number,
  support_version: string,
  subscription_link: string,
  source_code: string,
  manager_supported: boolean,
  container_version: string,
  container_image: string,
  container_type: IngestionConnectorType,
  config_schema: {
    $schema: string,
    $id: string,
    type: string,
    properties: {
      [key: string]: IngestionTypedProperty
    },
    required: string[],
    additionalProperties: boolean,
  }
}

const BrowseMoreButton = () => {
  const { t_i18n } = useFormatter();

  return (
    <GradientButton
      size="small"
      sx={{ marginLeft: 1 }}
      href={'https://filigran.notion.site/OpenCTI-Ecosystem-868329e9fb734fca89692b2ed6087e76'}
      target="_blank"
      title={t_i18n('Browse more')}
    >
      {t_i18n('Browse more')}
    </GradientButton>
  );
};

const CatalogsEmptyState = () => {
  const { t_i18n } = useFormatter();
  return (
    <Stack
      justifyContent="center"
      alignItems="center"
      sx={{
        minHeight: '50vh',
      }}
    >
      <GradientCard sx={{
        px: 10,
        display: 'flex',
        flexDirection: 'column',
        alignItems: 'center',
        gap: 4,
      }}
      >
        <Stack flexDirection="row" alignItems="flex-start" gap={1}>
          <GradientCard.Icon icon={Search} size="large" />
          <Stack>
            <GradientCard.Text sx={{ whiteSpace: 'pre' }}>{t_i18n('Sorry, we couldn\'t find any results for your search.')}</GradientCard.Text>
            <GradientCard.Text sx={{ whiteSpace: 'pre' }}>{t_i18n('For more results, you can search in the ecosystem.')}</GradientCard.Text>
          </Stack>
        </Stack>
        <BrowseMoreButton />
      </GradientCard>
    </Stack>
  );
};

const IngestionCatalogComponent = ({
  catalogsData,
  deploymentData,
  onClickDeploy,
}: IngestionCatalogComponentProps) => {
  const isEnterpriseEdition = useEnterpriseEdition();
  const { t_i18n } = useFormatter();
  const { setTitle } = useConnectedDocumentModifier();
  const [searchParams] = useSearchParams();

  const { hasActiveManagers } = useConnectorManagerStatus();

  setTitle(t_i18n('Connector catalog | Ingestion | Data'));

  const catalogs = catalogsData.catalogs || [];
  const { connectors } = deploymentData;

  const { filteredCatalogs, filters, setFilters } = useIngestionCatalogFilters({
    catalogs,
    searchParams,
  });

  const allContracts: IngestionConnector[] = [];

  for (const catalog of catalogs) {
    for (const contract of catalog.contracts) {
      try {
        const parsedContract = JSON.parse(contract);
        allContracts.push(parsedContract);
      } catch (_e) {
        MESSAGING$.notifyError(t_i18n('Failed to parse a contract'));
      }
    }
  }

  const deploymentCounts = createDeploymentCountMap(connectors);

  return (
    <div data-testid="catalog-page">
      <IngestionMenu />
      <PageContainer withRightMenu withGap>
        <Breadcrumbs elements={[{ label: t_i18n('Data') }, { label: t_i18n('Ingestion') }, { label: t_i18n('Connector catalog'), current: true }]} />
        <ConnectorDeploymentBanner hasActiveManagers={hasActiveManagers} />
        <Stack flexDirection="row">
          <IngestionCatalogFilters
            contracts={allContracts}
            filters={filters}
            onFiltersChange={setFilters}
          />
          <BrowseMoreButton />
        </Stack>

        <Grid container spacing={2}>
          {filteredCatalogs.map((catalog) => {
            return catalog.contracts.map((contract) => {
              const deploymentCount = deploymentCounts.get(contract.container_image) ?? 0;
              return (
                <Grid
                  key={contract.title}
                  size={{ xs: 12, md: 6, lg: 4, xl: 3 }}
                >
                  <IngestionCatalogCard
                    node={contract}
                    dataListId={catalog.id}
                    isEnterpriseEdition={isEnterpriseEdition}
                    onClickDeploy={() => onClickDeploy(contract, catalog.id, hasActiveManagers, deploymentCount)}
                    deploymentCount={deploymentCount}
                  />
                </Grid>
              );
            });
          })}
        </Grid>

        {filteredCatalogs.length === 0 && (
          <CatalogsEmptyState />
        )}
      </PageContainer>
    </div>
  );
};

const IngestionCatalog = () => {
  const { catalogState, handleOpenDeployDialog, handleCloseDeployDialog, handleCreate } = useConnectorDeployDialog();

  const [catalogsRef, loadCatalogs] = useQueryLoader<IngestionConnectorsCatalogsQuery>(ingestionConnectorsCatalogsQuery);
  const [deploymentRef, loadDeployment] = useQueryLoader<IngestionConnectorsQuery>(ingestionConnectorsQuery);

  useEffect(() => {
    // fetch once the catalogs and use the cache during runtime
    loadCatalogs({}, { fetchPolicy: 'store-or-network' });
    loadDeployment({}, { fetchPolicy: 'store-and-network' });
  }, []);

  if (!deploymentRef || !catalogsRef) {
    return <Loader variant={LoaderVariant.container} />;
  }

  return (
    <>
      <Suspense fallback={<Loader variant={LoaderVariant.container} />}>
        <ConnectorManagerStatusProvider>
          {catalogsRef && (
            <IngestionConnectorsCatalogs queryRef={catalogsRef}>
              {({ data: catalogsData }) => (
                <IngestionConnectors queryRef={deploymentRef}>
                  {({ data: deploymentData }) => (
                    <IngestionCatalogComponent
                      catalogsData={catalogsData}
                      deploymentData={deploymentData}
                      onClickDeploy={handleOpenDeployDialog}
                    />
                  )}
                </IngestionConnectors>
              )}
            </IngestionConnectorsCatalogs>
          )}
        </ConnectorManagerStatusProvider>
      </Suspense>

      {catalogState.selectedConnector && (
        <IngestionCatalogConnectorCreation
          open={!!catalogState.selectedConnector}
          connector={catalogState.selectedConnector}
          onClose={handleCloseDeployDialog}
          catalogId={catalogState.selectedCatalogId}
          hasActiveManagers={catalogState.hasActiveManagers}
          onCreate={handleCreate}
          deploymentCount={catalogState.deploymentCount}
        />
      )}
    </>
  );
};

export default IngestionCatalog;
