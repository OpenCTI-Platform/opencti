import React, { ChangeEvent, Suspense, useContext, useEffect, useMemo, useState } from 'react';
import IngestionMenu from '@components/data/IngestionMenu';
import { useQueryLoader } from 'react-relay';
import IngestionCatalogCard from '@components/data/IngestionCatalog/IngestionCatalogCard';
import useIngestionCatalogFilters, { CatalogSection, CatalogSortMode } from '@components/data/IngestionCatalog/hooks/useIngestionCatalogFilters';
import { useSearchParams } from 'react-router-dom';
import { Box, Chip, MenuItem, Stack, TextField, Typography } from '@mui/material';
import { ExtensionOutlined, HubOutlined, Search, VerifiedOutlined, WorkspacesOutlined } from '@mui/icons-material';
import type { SvgIconComponent } from '@mui/icons-material';
import Grid from '@mui/material/Grid2';
import { alpha, useTheme } from '@mui/material/styles';
import { ConnectorManagerStatusProvider, useConnectorManagerStatus } from '@components/data/connectors/ConnectorManagerStatusContext';
import ConnectorDeploymentBanner from '@components/data/connectors/ConnectorDeploymentBanner';
import IngestionCatalogConnectorCreation from '@components/data/IngestionCatalog/IngestionCatalogConnectorCreation';
import { getConnectorMetadata, getConnectorTypeIcon, IngestionConnectorType } from '@components/data/IngestionCatalog/utils/ingestionConnectorTypeMetadata';
import createDeploymentCountMap from '@components/data/IngestionCatalog/utils/createDeploymentCountMap';
import useConnectorDeployDialog from '@components/data/IngestionCatalog/hooks/useConnectorDeployDialog';
import { IngestionConnectorsCatalogsQuery } from '@components/data/IngestionCatalog/__generated__/IngestionConnectorsCatalogsQuery.graphql';
import IngestionConnectorsCatalogs, { ingestionConnectorsCatalogsQuery } from '@components/data/IngestionCatalog/IngestionConnectorsCatalog';
import { IngestionConnectorsQuery } from '@components/data/IngestionCatalog/__generated__/IngestionConnectorsQuery.graphql';
import IngestionConnectors, { ingestionConnectorsQuery } from '@components/data/IngestionCatalog/IngestionConnectors';
import IngestionCatalogFacetSidebar, { useCatalogStatusLabel } from '@components/data/IngestionCatalog/IngestionCatalogFacetSidebar';
import Breadcrumbs from '../../../components/Breadcrumbs';
import { useFormatter } from '../../../components/i18n';
import useConnectedDocumentModifier from '../../../utils/hooks/useConnectedDocumentModifier';
import PageContainer from '../../../components/PageContainer';
import Loader, { LoaderVariant } from '../../../components/Loader';
import Button from '@common/button/Button';
import GradientCard from '../../../components/GradientCard';
import useEnterpriseEdition from '../../../utils/hooks/useEnterpriseEdition';
import { UserContext } from '../../../utils/hooks/useAuth';
import { isNotEmptyField } from '../../../utils/utils';
import SearchInput from '../../../components/SearchInput';

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
      href={browseHubCatalog}
      target="_blank"
      title={t_i18n('Browse More')}
    >
      {t_i18n('Browse More')}
    </Button>
  );
};

interface HeroStatChipProps {
  icon: SvgIconComponent;
  value: number;
  label: string;
}

const HeroStatChip = ({ icon: Icon, value, label }: HeroStatChipProps) => {
  const theme = useTheme();
  return (
    <Stack
      direction="row"
      alignItems="center"
      gap={0.75}
      sx={{
        paddingInline: 1.25,
        paddingBlock: 0.5,
        borderRadius: 1,
        border: `1px solid ${alpha(theme.palette.text.primary, 0.1)}`,
        backgroundColor: alpha(theme.palette.text.primary, 0.04),
      }}
    >
      <Icon sx={{ fontSize: 15, color: theme.palette.primary.main }} />
      <Typography sx={{ fontSize: 12, fontWeight: 600, fontVariantNumeric: 'tabular-nums' }}>
        {value}
      </Typography>
      <Typography sx={{ fontSize: 12, color: theme.palette.text.secondary }}>
        {label}
      </Typography>
    </Stack>
  );
};

interface CatalogHeroProps {
  connectorCount: number;
  typeCount: number;
  useCaseCount: number;
  verifiedCount: number;
}

const CatalogHero = ({ connectorCount, typeCount, useCaseCount, verifiedCount }: CatalogHeroProps) => {
  const { t_i18n } = useFormatter();
  const theme = useTheme();
  return (
    <Box
      sx={{
        position: 'relative',
        overflow: 'hidden',
        borderRadius: 1,
        border: `1px solid ${alpha(theme.palette.text.primary, 0.08)}`,
        backgroundColor: theme.palette.background.paper,
        padding: 3,
      }}
    >
      <Box
        sx={{
          pointerEvents: 'none',
          position: 'absolute',
          top: -100,
          right: -60,
          width: 260,
          height: 260,
          borderRadius: '50%',
          background: alpha(theme.palette.primary.main, 0.08),
          filter: 'blur(60px)',
        }}
      />
      <Stack direction="row" justifyContent="space-between" alignItems="flex-start" gap={2} sx={{ position: 'relative' }}>
        <Box>
          <Typography
            variant="h1"
            sx={{
              fontWeight: 700,
              fontSize: 22,
              marginBottom: 0.5,
            }}
          >
            {t_i18n('Connector catalog')}
          </Typography>
          <Typography variant="body2" sx={{ color: theme.palette.text.secondary, maxWidth: 640 }}>
            {t_i18n('Browse, filter and deploy connectors to feed your platform with threat intelligence.')}
          </Typography>
          <Stack direction="row" flexWrap="wrap" gap={1} sx={{ marginTop: 2 }}>
            <HeroStatChip icon={ExtensionOutlined} value={connectorCount} label={t_i18n('Connectors')} />
            <HeroStatChip icon={HubOutlined} value={typeCount} label={t_i18n('Connector types')} />
            <HeroStatChip icon={WorkspacesOutlined} value={useCaseCount} label={t_i18n('Use cases')} />
            <HeroStatChip icon={VerifiedOutlined} value={verifiedCount} label={t_i18n('Verified')} />
          </Stack>
        </Box>
        <BrowseMoreButton />
      </Stack>
    </Box>
  );
};

interface CatalogsEmptyStateProps {
  hasActiveFilters: boolean;
  onResetFilters: () => void;
}

const CatalogsEmptyState = ({ hasActiveFilters, onResetFilters }: CatalogsEmptyStateProps) => {
  const { t_i18n } = useFormatter();
  return (
    <Stack
      justifyContent="center"
      alignItems="center"
      sx={{
        minHeight: '40vh',
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
        <Stack direction="row" gap={2}>
          {hasActiveFilters && (
            <Button variant="secondary" onClick={onResetFilters}>
              {t_i18n('Reset filters')}
            </Button>
          )}
          <BrowseMoreButton />
        </Stack>
      </GradientCard>
    </Stack>
  );
};

interface CatalogSectionHeaderProps {
  type: IngestionConnectorType;
  count: number;
}

const CatalogSectionHeader = ({ type, count }: CatalogSectionHeaderProps) => {
  const { t_i18n } = useFormatter();
  const theme = useTheme();
  const Icon = getConnectorTypeIcon(type);
  return (
    <Stack direction="row" alignItems="center" gap={1.25} sx={{ marginBottom: 1.5 }}>
      <Box
        sx={{
          width: 28,
          height: 28,
          display: 'flex',
          alignItems: 'center',
          justifyContent: 'center',
          borderRadius: 1,
          border: `1px solid ${alpha(theme.palette.primary.main, 0.2)}`,
          backgroundColor: alpha(theme.palette.primary.main, 0.1),
        }}
      >
        <Icon sx={{ fontSize: 15, color: theme.palette.primary.main }} />
      </Box>
      <Typography
        component="h2"
        sx={{
          fontFamily: theme.typography.h1.fontFamily,
          fontSize: 14,
          fontWeight: 600,
        }}
      >
        {getConnectorMetadata(type, t_i18n).label}
      </Typography>
      <Box
        component="span"
        sx={{
          paddingInline: 0.75,
          paddingBlock: '1px',
          borderRadius: 0.5,
          backgroundColor: alpha(theme.palette.text.primary, 0.06),
          fontSize: 10,
          fontWeight: 500,
          fontVariantNumeric: 'tabular-nums',
          color: theme.palette.text.secondary,
        }}
      >
        {count}
      </Box>
      <Box sx={{ flex: 1, height: '1px', backgroundColor: alpha(theme.palette.text.primary, 0.05) }} />
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
  const theme = useTheme();
  const { setTitle } = useConnectedDocumentModifier();
  const [searchParams] = useSearchParams();
  const statusLabel = useCatalogStatusLabel();

  const { hasActiveManagers } = useConnectorManagerStatus();

  setTitle(t_i18n('Connector catalog | Ingestion | Data'));

  const catalogs = catalogsData.catalogs || [];
  const { connectors } = deploymentData;

  // Memoized so its identity stays stable across renders: it feeds the
  // contract-parsing useMemo in useIngestionCatalogFilters.
  const deploymentCounts = useMemo(() => createDeploymentCountMap(connectors), [connectors]);

  const {
    entries,
    filteredEntries,
    sections,
    filters,
    setFilters,
    sort,
    setSort,
    hasActiveFilters,
    clearAllFilters,
    facets,
  } = useIngestionCatalogFilters({
    catalogs,
    deploymentCounts,
    searchParams,
  });

  const [searchInput, setSearchInput] = useState(filters.search);

  const handleSearchInputSubmit = (value: string) => {
    setSearchInput(value);
    setFilters({ ...filters, search: value });
  };

  const handleSearchInputChange = (event: ChangeEvent<HTMLInputElement>) => {
    const { value } = event.currentTarget;
    setSearchInput(value);
    if (!value) {
      setFilters({ ...filters, search: '' });
    }
  };

  const handleResetFilters = () => {
    setSearchInput('');
    clearAllFilters();
  };

  const verifiedCount = entries.filter((entry) => entry.connector.verified).length;

  const activeChips = [
    ...filters.types.map((type) => ({
      key: `type-${type}`,
      label: getConnectorMetadata(type as IngestionConnectorType, t_i18n).label,
      remove: () => setFilters({ ...filters, types: filters.types.filter((v) => v !== type) }),
    })),
    ...filters.useCases.map((useCase) => ({
      key: `useCase-${useCase}`,
      label: useCase,
      remove: () => setFilters({ ...filters, useCases: filters.useCases.filter((v) => v !== useCase) }),
    })),
    ...filters.statuses.map((status) => ({
      key: `status-${status}`,
      label: statusLabel(status),
      remove: () => setFilters({ ...filters, statuses: filters.statuses.filter((v) => v !== status) }),
    })),
  ];

  return (
    <div data-testid="catalog-page">
      <IngestionMenu />
      <PageContainer withRightMenu withGap>
        <Breadcrumbs elements={[{ label: t_i18n('Data') }, { label: t_i18n('Ingestion') }, { label: t_i18n('Connector catalog'), current: true }]} />
        <ConnectorDeploymentBanner hasActiveManagers={hasActiveManagers} />

        <CatalogHero
          connectorCount={entries.length}
          typeCount={facets.types.length}
          useCaseCount={facets.useCases.length}
          verifiedCount={verifiedCount}
        />

        <Stack direction="row" gap={2} alignItems="flex-start">
          <IngestionCatalogFacetSidebar
            filters={filters}
            onFiltersChange={setFilters}
            hasActiveFilters={hasActiveFilters}
            onClearAll={handleResetFilters}
            facets={facets}
          />

          <Box sx={{ flex: 1, minWidth: 0, display: 'flex', flexDirection: 'column', gap: 2 }}>
            <Stack direction="row" alignItems="center" flexWrap="wrap" gap={2}>
              <SearchInput
                value={searchInput}
                onSubmit={handleSearchInputSubmit}
                onChange={handleSearchInputChange}
              />
              <TextField
                select
                size="small"
                variant="outlined"
                label={t_i18n('Sort by')}
                value={sort}
                onChange={(event) => setSort(event.target.value as CatalogSortMode)}
                sx={{ width: 200, backgroundColor: theme.palette.background.paper }}
              >
                <MenuItem value="name">{t_i18n('Name (A-Z)')}</MenuItem>
                <MenuItem value="deployed">{t_i18n('Most deployed')}</MenuItem>
                <MenuItem value="verified">{t_i18n('Verified first')}</MenuItem>
              </TextField>
              <Box
                component="span"
                sx={{
                  marginLeft: 'auto',
                  paddingInline: 1.25,
                  paddingBlock: 0.5,
                  borderRadius: 1,
                  backgroundColor: alpha(theme.palette.text.primary, 0.06),
                  fontSize: 12,
                  fontWeight: 500,
                  fontVariantNumeric: 'tabular-nums',
                  color: theme.palette.text.secondary,
                }}
              >
                {(() => {
                  if (filteredEntries.length === 1) return t_i18n('1 result');
                  return t_i18n('{count} results', { values: { count: filteredEntries.length } });
                })()}
              </Box>
            </Stack>

            {activeChips.length > 0 && (
              <Stack direction="row" alignItems="center" flexWrap="wrap" gap={1}>
                {activeChips.map((chip) => (
                  <Chip
                    key={chip.key}
                    size="small"
                    label={chip.label}
                    onDelete={chip.remove}
                    sx={{
                      borderRadius: 1,
                      border: `1px solid ${alpha(theme.palette.primary.main, 0.3)}`,
                      backgroundColor: alpha(theme.palette.primary.main, 0.1),
                      color: theme.palette.primary.main,
                    }}
                  />
                ))}
                <Button variant="tertiary" size="small" onClick={handleResetFilters}>
                  {t_i18n('Clear all')}
                </Button>
              </Stack>
            )}

            {sections.length === 0 ? (
              <CatalogsEmptyState
                hasActiveFilters={hasActiveFilters}
                onResetFilters={handleResetFilters}
              />
            ) : (
              <Box sx={{ display: 'flex', flexDirection: 'column', gap: 4 }}>
                {sections.map((section: CatalogSection) => (
                  <Box component="section" key={section.type}>
                    <CatalogSectionHeader type={section.type} count={section.entries.length} />
                    <Grid container spacing={2}>
                      {section.entries.map((entry) => (
                        <Grid
                          key={`${entry.catalogId}-${entry.connector.slug}`}
                          size={{ xs: 12, md: 6, lg: 4, xl: 3 }}
                        >
                          <IngestionCatalogCard
                            node={entry.connector}
                            dataListId={entry.catalogId}
                            isEnterpriseEdition={isEnterpriseEdition}
                            onClickDeploy={() => onClickDeploy(entry.connector, entry.catalogId, hasActiveManagers, entry.deploymentCount)}
                            deploymentCount={entry.deploymentCount}
                          />
                        </Grid>
                      ))}
                    </Grid>
                  </Box>
                ))}
              </Box>
            )}
          </Box>
        </Stack>
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
