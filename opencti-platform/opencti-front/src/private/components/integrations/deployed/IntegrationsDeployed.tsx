import React, { ChangeEvent, Suspense, useCallback, useEffect, useMemo, useState } from 'react';
import { Link, useSearchParams } from 'react-router-dom';
import { Box, MenuItem, Stack, TextField } from '@mui/material';
import Grid from '@mui/material/Grid2';
import { useTheme } from '@mui/material/styles';
import { useQueryLoader } from 'react-relay';
import { interval } from 'rxjs';
import Button from '@common/button/Button';
import ConnectorsList, { connectorsListQuery } from '@components/data/connectors/ConnectorsList';
import ConnectorsLogos, { connectorsLogosQuery } from '@components/data/connectors/ConnectorsLogos';
import ConnectorsState, { connectorsStateQuery } from '@components/data/connectors/ConnectorsState';
import { ConnectorsListQuery } from '@components/data/connectors/__generated__/ConnectorsListQuery.graphql';
import { ConnectorsLogosQuery } from '@components/data/connectors/__generated__/ConnectorsLogosQuery.graphql';
import { ConnectorsStateQuery } from '@components/data/connectors/__generated__/ConnectorsStateQuery.graphql';
import DeployedFacetSidebar, { useDeployedTypeMetadata } from '@components/integrations/deployed/DeployedFacetSidebar';
import DeployedIntegrationCard from '@components/integrations/deployed/DeployedIntegrationCard';
import useDeployedIntegrations from '@components/integrations/deployed/useDeployedIntegrations';
import useDeployedIntegrationsFilters, { DeployedSection, DeployedSortMode } from '@components/integrations/deployed/useDeployedIntegrationsFilters';
import { MarketplaceEmptyState, MarketplaceSectionHeader, ResultCountChip } from '@components/integrations/components/MarketplaceUi';
import useProgressiveReveal from '@components/integrations/components/useProgressiveReveal';
import { IntegrationsData } from '@components/integrations/Integrations';
import { useFormatter } from '../../../../components/i18n';
import Loader, { LoaderVariant } from '../../../../components/Loader';
import SearchInput from '../../../../components/SearchInput';
import useGranted, { MODULES } from '../../../../utils/hooks/useGranted';
import { FIVE_SECONDS } from '../../../../utils/Time';

const interval$ = interval(FIVE_SECONDS);

interface IntegrationsDeployedContentProps {
  data: IntegrationsData;
  connectorsListData: ConnectorsListQuery['response'] | null;
  connectorsStateData: ConnectorsStateQuery['response'] | null;
  logosBySlug: Map<string, string>;
  onConnectorsChange: () => void;
}

const IntegrationsDeployedContent = ({
  data,
  connectorsListData,
  connectorsStateData,
  logosBySlug,
  onConnectorsChange,
}: IntegrationsDeployedContentProps) => {
  const { t_i18n } = useFormatter();
  const theme = useTheme();
  const [searchParams] = useSearchParams();
  const typeMetadata = useDeployedTypeMetadata();
  const { feedsData, formsData, refetchFeeds, refetchForms } = data;

  const items = useDeployedIntegrations({
    connectorsListData,
    connectorsStateData,
    feedsData,
    formsData,
    logosBySlug,
  });

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
  } = useDeployedIntegrationsFilters({ items, searchParams });

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

  const handleItemChange = useCallback(() => {
    onConnectorsChange();
    refetchFeeds();
    refetchForms();
  }, [onConnectorsChange, refetchFeeds, refetchForms]);

  // Progressive mounting while scrolling, as on the available tab.
  const revealResetKey = JSON.stringify({ filters, sort });
  const { visibleCount, sentinelRef, hasMore } = useProgressiveReveal(filteredItems.length, revealResetKey);
  const visibleSections = useMemo(() => {
    const result: (DeployedSection & { totalCount: number })[] = [];
    let remaining = visibleCount;
    for (const section of sections) {
      if (remaining <= 0) break;
      result.push({
        ...section,
        items: section.items.slice(0, remaining),
        totalCount: section.items.length,
      });
      remaining -= section.items.length;
    }
    return result;
  }, [sections, visibleCount]);

  return (
    <Stack direction="row" gap={2} alignItems="flex-start">
      <DeployedFacetSidebar
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
            onChange={(event) => setSort(event.target.value as DeployedSortMode)}
            sx={{ width: 200, backgroundColor: theme.palette.background.paper }}
          >
            <MenuItem value="name">{t_i18n('Name (A-Z)')}</MenuItem>
            <MenuItem value="status">{t_i18n('Status')}</MenuItem>
            <MenuItem value="lastRun">{t_i18n('Last run')}</MenuItem>
          </TextField>
          <ResultCountChip count={filteredItems.length} />
        </Stack>

        {sections.length === 0 ? (
          <MarketplaceEmptyState
            hasActiveFilters={hasActiveFilters}
            onResetFilters={handleResetFilters}
            extraAction={(
              <Button
                component={Link}
                to="/dashboard/integrations/available"
              >
                {t_i18n('Browse the catalog')}
              </Button>
            )}
          />
        ) : (
          <Box sx={{ display: 'flex', flexDirection: 'column', gap: 4 }}>
            {visibleSections.map((section) => {
              const { label, icon } = typeMetadata(section.key);
              return (
                <Box component="section" key={section.key}>
                  <MarketplaceSectionHeader
                    icon={icon}
                    label={label}
                    count={section.totalCount}
                  />
                  <Grid container spacing={2}>
                    {section.items.map((item) => (
                      <Grid
                        key={item.id}
                        size={{ xs: 12, md: 6, lg: 4, xl: 3 }}
                      >
                        <DeployedIntegrationCard item={item} onChange={handleItemChange} />
                      </Grid>
                    ))}
                  </Grid>
                </Box>
              );
            })}
            {hasMore && <Box ref={sentinelRef} sx={{ height: 1 }} />}
          </Box>
        )}
      </Box>
    </Stack>
  );
};

interface IntegrationsDeployedProps {
  data: IntegrationsData;
}

// The deployed tab: registered connectors and built-in feed instances merged
// in a single faceted marketplace view, with live monitoring metrics.
const IntegrationsDeployed = ({ data }: IntegrationsDeployedProps) => {
  const isConnectorReader = useGranted([MODULES]);

  const [connectorsListRef, loadConnectorsList] = useQueryLoader<ConnectorsListQuery>(connectorsListQuery);
  const [connectorsStateRef, loadConnectorsState] = useQueryLoader<ConnectorsStateQuery>(connectorsStateQuery);
  const [connectorsLogosRef, loadConnectorsLogos] = useQueryLoader<ConnectorsLogosQuery>(connectorsLogosQuery);
  const [logosBySlug, setLogosBySlug] = useState<Map<string, string>>(new Map());

  useEffect(() => {
    if (!isConnectorReader) return undefined;
    loadConnectorsList({}, { fetchPolicy: 'store-and-network' });
    loadConnectorsState({}, { fetchPolicy: 'store-and-network' });
    loadConnectorsLogos({}, { fetchPolicy: 'store-and-network' });
    // Live state refresh, as on the legacy monitoring screen.
    const subscription = interval$.subscribe(() => {
      loadConnectorsState({}, { fetchPolicy: 'store-and-network' });
    });
    return () => subscription.unsubscribe();
  }, []);

  const onConnectorsChange = useCallback(() => {
    if (!isConnectorReader) return;
    // store-and-network keeps the current cards rendered while refreshing.
    loadConnectorsList({}, { fetchPolicy: 'store-and-network' });
    loadConnectorsState({}, { fetchPolicy: 'store-and-network' });
  }, [isConnectorReader]);

  const renderContent = (
    connectorsListData: ConnectorsListQuery['response'] | null,
    connectorsStateData: ConnectorsStateQuery['response'] | null,
  ) => (
    <IntegrationsDeployedContent
      data={data}
      connectorsListData={connectorsListData}
      connectorsStateData={connectorsStateData}
      logosBySlug={logosBySlug}
      onConnectorsChange={onConnectorsChange}
    />
  );

  if (isConnectorReader && (!connectorsListRef || !connectorsStateRef)) {
    return <Loader variant={LoaderVariant.container} />;
  }

  return (
    <Suspense fallback={<Loader variant={LoaderVariant.container} />}>
      {isConnectorReader && connectorsListRef && connectorsStateRef ? (
        <ConnectorsList queryRef={connectorsListRef}>
          {({ data: connectorsListData }) => (
            <ConnectorsState queryRef={connectorsStateRef}>
              {({ data: connectorsStateData }) => (
                <>
                  {renderContent(connectorsListData, connectorsStateData)}
                  {connectorsLogosRef && (
                    <Suspense fallback={null}>
                      <ConnectorsLogos
                        queryRef={connectorsLogosRef}
                        onLoaded={setLogosBySlug}
                      />
                    </Suspense>
                  )}
                </>
              )}
            </ConnectorsState>
          )}
        </ConnectorsList>
      ) : (
        renderContent(null, null)
      )}
    </Suspense>
  );
};

export default IntegrationsDeployed;
