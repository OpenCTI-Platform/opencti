import React, { Suspense, useCallback, useContext, useEffect, useRef, useState } from 'react';
import IngestionMenu from '@components/data/IngestionMenu';
import { useQueryLoader } from 'react-relay';
import IngestionCatalogCard from '@components/data/IngestionCatalog/IngestionCatalogCard';
import useIngestionCatalogFilters from '@components/data/IngestionCatalog/hooks/useIngestionCatalogFilters';
import { useSearchParams } from 'react-router-dom';
import { Skeleton, Stack } from '@mui/material';
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
import Button from '@common/button/Button';
import IngestionCatalogFilters from './IngestionCatalog/IngestionCatalogFilters';
import GradientCard from '../../../components/GradientCard';
import { MESSAGING$ } from '../../../relay/environment';
import useEnterpriseEdition from '../../../utils/hooks/useEnterpriseEdition';
import { UserContext } from '../../../utils/hooks/useAuth';
import { isNotEmptyField } from '../../../utils/utils';

const CATALOG_POLL_INTERVAL_MS = 5000;

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
  title: string;
  slug: string;
  description: string;
  short_description: string;
  logo: string;
  use_cases: string[];
  verified: boolean;
  last_verified_date: string;
  playbook_supported: boolean;
  max_confidence_level: number;
  support_version: string;
  subscription_link: string;
  source_code: string;
  manager_supported: boolean;
  container_version: string;
  container_image: string;
  container_type: IngestionConnectorType;
  config_schema: {
    $schema: string;
    $id: string;
    type: string;
    properties: {
      [key: string]: IngestionTypedProperty;
    };
    required: string[];
    additionalProperties: boolean;
  };
}

const BrowseMoreButton = () => {
  const { t_i18n } = useFormatter();
  const { settings } = useContext(UserContext);
  const browseHubCatalog = isNotEmptyField(settings?.platform_xtmhub_url)
    ? `${settings.platform_xtmhub_url}/cybersecurity-solutions/open-cti-integrations`
    : '';
  return (
    <Button
      gradient
      variant="secondary"
      style={{ marginTop: 9, marginBottom: 10 }}
      href={browseHubCatalog}
      target="_blank"
      title={t_i18n('Browse More')}
    >
      {t_i18n('Browse More')}
    </Button>
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

const IngestionCatalogSkeleton = () => {
  const { t_i18n } = useFormatter();

  return (
    <div data-testid="catalog-page-skeleton">
      <IngestionMenu />
      <PageContainer withRightMenu withGap>
        <Breadcrumbs elements={[{ label: t_i18n('Data') }, { label: t_i18n('Ingestion') }, { label: t_i18n('Connector catalog'), current: true }]} />

        <Stack flexDirection="row" justifyContent="space-between" alignItems="center" sx={{ mb: 2 }}>
          <Stack direction="row" spacing={1}>
            <Skeleton variant="rounded" width={220} height={40} />
            <Skeleton variant="rounded" width={180} height={40} />
          </Stack>
          <Skeleton variant="rounded" width={130} height={40} />
        </Stack>

        <Grid container spacing={2}>
          {Array.from({ length: 8 }).map((_, index) => (
            <Grid
              key={`skeleton-card-${index}`}
              size={{ xs: 12, md: 6, lg: 4, xl: 3 }}
            >
              <Stack
                spacing={1.2}
                sx={{
                  p: 2,
                  borderRadius: 2,
                  border: (theme) => `1px solid ${theme.palette.divider}`,
                }}
              >
                <Skeleton variant="rounded" width="100%" height={120} />
                <Skeleton variant="text" width="70%" height={34} />
                <Skeleton variant="text" width="95%" />
                <Skeleton variant="text" width="90%" />
                <Stack direction="row" spacing={1} sx={{ pt: 1 }}>
                  <Skeleton variant="rounded" width={72} height={24} />
                  <Skeleton variant="rounded" width={84} height={24} />
                </Stack>
                <Skeleton variant="rounded" width="100%" height={36} sx={{ mt: 1 }} />
              </Stack>
            </Grid>
          ))}
        </Grid>
      </PageContainer>
    </div>
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
  const [hasCatalogResults, setHasCatalogResults] = useState(false);
  const lastSeenCatalogRevision = useRef<string | null | undefined>(undefined);

  const [catalogsRef, loadCatalogs] = useQueryLoader<IngestionConnectorsCatalogsQuery>(ingestionConnectorsCatalogsQuery);
  const [deploymentRef, loadDeployment] = useQueryLoader<IngestionConnectorsQuery>(ingestionConnectorsQuery);

  const handleCatalogsResolved = useCallback((catalogs: IngestionConnectorsCatalogsQuery['response']['catalogs']) => {
    if ((catalogs?.length ?? 0) > 0) {
      setHasCatalogResults(true);
    }
  }, []);

  const handleCatalogVersionChange = useCallback((revision: string | null) => {
    const prev = lastSeenCatalogRevision.current;

    // Track null revisions so we can detect when the remote catalog first becomes available.
    if (!revision) {
      lastSeenCatalogRevision.current = null;
      return;
    }

    // Component just mounted and remote catalog is already available: establish baseline, no refetch.
    if (prev === undefined) {
      lastSeenCatalogRevision.current = revision;
      return;
    }

    // Refetch when revision changes OR when remote catalog just became available after loading
    // (prev === null means we were in loading state and showed the embedded catalog as baseline).
    if (prev !== revision) {
      lastSeenCatalogRevision.current = revision;
      loadCatalogs({}, { fetchPolicy: 'network-only' });
    }
  }, [loadCatalogs]);

  useEffect(() => {
    // Initial bootstrap fetch.
    loadCatalogs({}, { fetchPolicy: 'store-or-network' });
    loadDeployment({}, { fetchPolicy: 'store-and-network' });
  }, [loadCatalogs, loadDeployment]);

  useEffect(() => {
    if (!catalogsRef || hasCatalogResults) {
      return undefined;
    }

    // Retry while the catalog manager is still loading and catalogs are empty.
    const intervalId = setInterval(() => {
      loadCatalogs({}, { fetchPolicy: 'network-only' });
    }, CATALOG_POLL_INTERVAL_MS);

    return () => {
      clearInterval(intervalId);
    };
  }, [catalogsRef, hasCatalogResults, loadCatalogs]);

  if (!deploymentRef || !catalogsRef) {
    return <IngestionCatalogSkeleton />;
  }

  return (
    <>
      <Suspense fallback={<IngestionCatalogSkeleton />}>
        <ConnectorManagerStatusProvider onCatalogVersionChange={handleCatalogVersionChange}>
          {catalogsRef && (
            <IngestionConnectorsCatalogs queryRef={catalogsRef} onCatalogsResolved={handleCatalogsResolved}>
              {({ data: catalogsData }) => {
                const currentCatalogsCount = catalogsData.catalogs?.length ?? 0;
                const shouldRenderCatalogLoader = !hasCatalogResults && currentCatalogsCount === 0;

                if (shouldRenderCatalogLoader) {
                  return <IngestionCatalogSkeleton />;
                }

                return (
                  <IngestionConnectors queryRef={deploymentRef}>
                    {({ data: deploymentData }) => (
                      <IngestionCatalogComponent
                        catalogsData={catalogsData}
                        deploymentData={deploymentData}
                        onClickDeploy={handleOpenDeployDialog}
                      />
                    )}
                  </IngestionConnectors>
                );
              }}
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
