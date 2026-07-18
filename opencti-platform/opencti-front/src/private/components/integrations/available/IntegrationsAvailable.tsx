import React, { ChangeEvent, useMemo, useState } from 'react';
import { useSearchParams } from 'react-router-dom';
import { Box, MenuItem, Stack, TextField } from '@mui/material';
import { WidgetsOutlined } from '@mui/icons-material';
import Grid from '@mui/material/Grid2';
import { useTheme } from '@mui/material/styles';
import { useConnectorManagerStatus } from '@components/data/connectors/ConnectorManagerStatusContext';
import IngestionCatalogCard from '@components/integrations/catalog/IngestionCatalogCard';
import IngestionCatalogConnectorCreation from '@components/integrations/catalog/IngestionCatalogConnectorCreation';
import IngestionCatalogFacetSidebar from '@components/integrations/catalog/IngestionCatalogFacetSidebar';
import useConnectorDeployDialog from '@components/integrations/catalog/hooks/useConnectorDeployDialog';
import useIngestionCatalogFilters, {
  BUILT_IN_SECTION_KEY,
  BuiltInCatalogInput,
  CatalogItem,
  CatalogSection,
  CatalogSortMode,
} from '@components/integrations/catalog/hooks/useIngestionCatalogFilters';
import createDeploymentCountMap from '@components/integrations/catalog/utils/createDeploymentCountMap';
import { getConnectorMetadata, getConnectorTypeIcon, IngestionConnectorType } from '@components/integrations/catalog/utils/ingestionConnectorTypeMetadata';
import { BUILT_IN_INTEGRATIONS, BuiltInIntegrationKind } from '@components/integrations/available/builtInIntegrations';
import BuiltInIntegrationCard from '@components/integrations/available/BuiltInIntegrationCard';
import BuiltInIntegrationCreation from '@components/integrations/available/BuiltInIntegrationCreation';
import { BrowseMoreButton, MarketplaceEmptyState, MarketplaceSectionHeader, ResultCountChip } from '@components/integrations/components/MarketplaceUi';
import { IntegrationsData } from '@components/integrations/Integrations';
import { useFormatter } from '../../../../components/i18n';
import useEnterpriseEdition from '../../../../utils/hooks/useEnterpriseEdition';
import SearchInput from '../../../../components/SearchInput';

interface IntegrationsAvailableProps {
  data: IntegrationsData;
}

const IntegrationsAvailable = ({ data }: IntegrationsAvailableProps) => {
  const isEnterpriseEdition = useEnterpriseEdition();
  const { t_i18n } = useFormatter();
  const theme = useTheme();
  const [searchParams] = useSearchParams();
  const { hasActiveManagers } = useConnectorManagerStatus();
  const { catalogsData, deploymentData, feedsData, formsData, refetchFeeds, refetchForms } = data;

  const { catalogState, handleOpenDeployDialog, handleCloseDeployDialog, handleCreate } = useConnectorDeployDialog();
  const [builtInCreationKind, setBuiltInCreationKind] = useState<BuiltInIntegrationKind | null>(null);

  const catalogs = catalogsData?.catalogs ?? [];
  const connectors = deploymentData?.connectors ?? null;

  // Memoized so its identity stays stable across renders: it feeds the
  // contract-parsing useMemo in useIngestionCatalogFilters.
  const deploymentCounts = useMemo(() => createDeploymentCountMap(connectors ?? []), [connectors]);

  // Built-in ingestion methods, with their live instance counts.
  const builtIns: BuiltInCatalogInput[] = useMemo(() => {
    const countsByKind: Record<BuiltInIntegrationKind, number> = {
      sync: feedsData?.synchronizers?.pageInfo?.globalCount ?? 0,
      taxii: feedsData?.ingestionTaxiis?.pageInfo?.globalCount ?? 0,
      'taxii-push': feedsData?.ingestionTaxiiCollections?.pageInfo?.globalCount ?? 0,
      rss: feedsData?.ingestionRsss?.pageInfo?.globalCount ?? 0,
      csv: feedsData?.ingestionCsvs?.pageInfo?.globalCount ?? 0,
      json: feedsData?.ingestionJsons?.pageInfo?.globalCount ?? 0,
      form: formsData?.forms?.pageInfo?.globalCount ?? 0,
    };
    return BUILT_IN_INTEGRATIONS.map((definition) => ({
      definition,
      deploymentCount: countsByKind[definition.kind],
    }));
  }, [feedsData, formsData]);

  const {
    filteredItems,
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
    builtIns,
    searchParams,
  });

  const [searchInput, setSearchInput] = useState(filters.search);

  const handleSearchInputSubmit = (value: string) => {
    setSearchInput(value);
    setFilters((prev) => ({ ...prev, search: value }));
  };

  const handleSearchInputChange = (event: ChangeEvent<HTMLInputElement>) => {
    const { value } = event.currentTarget;
    setSearchInput(value);
    if (!value) {
      setFilters((prev) => ({ ...prev, search: '' }));
    }
  };

  const handleResetFilters = () => {
    setSearchInput('');
    clearAllFilters();
  };

  const renderSectionHeader = (section: CatalogSection) => {
    if (section.key === BUILT_IN_SECTION_KEY) {
      return (
        <MarketplaceSectionHeader
          icon={WidgetsOutlined}
          label={t_i18n('Built-in ingestion')}
          count={section.items.length}
        />
      );
    }
    return (
      <MarketplaceSectionHeader
        icon={getConnectorTypeIcon(section.key)}
        label={getConnectorMetadata(section.key as IngestionConnectorType, t_i18n).label}
        count={section.items.length}
      />
    );
  };

  const renderItem = (item: CatalogItem) => {
    if (item.builtIn) {
      return (
        <BuiltInIntegrationCard
          definition={item.builtIn}
          deploymentCount={item.deploymentCount}
          onClickCreate={() => setBuiltInCreationKind(item.builtIn ? item.builtIn.kind : null)}
        />
      );
    }
    if (item.connector) {
      const { connector, catalogId } = item.connector;
      return (
        <IngestionCatalogCard
          node={connector}
          dataListId={catalogId}
          isEnterpriseEdition={isEnterpriseEdition}
          onClickDeploy={() => handleOpenDeployDialog(connector, catalogId, hasActiveManagers, item.deploymentCount)}
          deploymentCount={item.deploymentCount}
        />
      );
    }
    return null;
  };

  return (
    <div data-testid="catalog-page">
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
            <ResultCountChip count={filteredItems.length} />
          </Stack>

          {sections.length === 0 ? (
            <MarketplaceEmptyState
              hasActiveFilters={hasActiveFilters}
              onResetFilters={handleResetFilters}
              extraAction={<BrowseMoreButton />}
            />
          ) : (
            <Box sx={{ display: 'flex', flexDirection: 'column', gap: 4 }}>
              {sections.map((section) => (
                <Box component="section" key={section.key}>
                  {renderSectionHeader(section)}
                  <Grid container spacing={2}>
                    {section.items.map((item) => (
                      <Grid
                        key={item.key}
                        size={{ xs: 12, md: 6, lg: 4, xl: 3 }}
                      >
                        {renderItem(item)}
                      </Grid>
                    ))}
                  </Grid>
                </Box>
              ))}
            </Box>
          )}
        </Box>
      </Stack>

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

      <BuiltInIntegrationCreation
        kind={builtInCreationKind}
        onClose={() => {
          // Refresh the instance counters: creations insert into paginated
          // connections that are not mounted on this screen.
          if (builtInCreationKind === 'form') {
            refetchForms();
          } else {
            refetchFeeds();
          }
          setBuiltInCreationKind(null);
        }}
      />
    </div>
  );
};

export default IntegrationsAvailable;
