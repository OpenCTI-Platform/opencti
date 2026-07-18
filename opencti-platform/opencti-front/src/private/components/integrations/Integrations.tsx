import React, { Suspense, useEffect, useMemo } from 'react';
import { Link, Navigate, useParams } from 'react-router-dom';
import { Box, Stack, Tab, Tabs, Typography } from '@mui/material';
import { ExtensionOutlined, RocketLaunchOutlined, VerifiedOutlined, WidgetsOutlined } from '@mui/icons-material';
import { alpha, useTheme } from '@mui/material/styles';
import { useQueryLoader } from 'react-relay';
import { ConnectorManagerStatusProvider, useConnectorManagerStatus } from '@components/data/connectors/ConnectorManagerStatusContext';
import ConnectorDeploymentBanner from '@components/data/connectors/ConnectorDeploymentBanner';
import IngestionConnectorsCatalogs, { ingestionConnectorsCatalogsQuery } from '@components/integrations/catalog/IngestionConnectorsCatalog';
import IngestionConnectors, { ingestionConnectorsQuery } from '@components/integrations/catalog/IngestionConnectors';
import { IngestionConnectorsCatalogsQuery } from '@components/integrations/catalog/__generated__/IngestionConnectorsCatalogsQuery.graphql';
import { IngestionConnectorsQuery } from '@components/integrations/catalog/__generated__/IngestionConnectorsQuery.graphql';
import { IngestionConnector } from '@components/integrations/catalog/types';
import {
  IngestionFeeds,
  IngestionFeedsData,
  IngestionFeedsForms,
  IngestionFeedsFormsData,
  ingestionFeedsFormsQuery,
  ingestionFeedsQuery,
} from '@components/integrations/deployed/IngestionFeeds';
import { IngestionFeedsQuery } from '@components/integrations/deployed/__generated__/IngestionFeedsQuery.graphql';
import { IngestionFeedsFormsQuery } from '@components/integrations/deployed/__generated__/IngestionFeedsFormsQuery.graphql';
import { BUILT_IN_INTEGRATIONS } from '@components/integrations/available/builtInIntegrations';
import { BrowseMoreButton, HeroStatChip } from '@components/integrations/components/MarketplaceUi';
import IntegrationsAvailable from '@components/integrations/available/IntegrationsAvailable';
import IntegrationsDeployed from '@components/integrations/deployed/IntegrationsDeployed';
import IntegrationsStatsStrip from '@components/integrations/deployed/IntegrationsStatsStrip';
import { connectorIdFromIngestId } from '@components/integrations/deployed/useDeployedIntegrations';
import Breadcrumbs from '../../../components/Breadcrumbs';
import { useFormatter } from '../../../components/i18n';
import Loader, { LoaderVariant } from '../../../components/Loader';
import PageContainer from '../../../components/PageContainer';
import useConnectedDocumentModifier from '../../../utils/hooks/useConnectedDocumentModifier';
import useGranted, { INGESTION, KNOWLEDGE_KNASKIMPORT, KNOWLEDGE_KNUPDATE, MODULES } from '../../../utils/hooks/useGranted';

export type IntegrationsTab = 'deployed' | 'available';

const FEEDS_PAGE_SIZE = 500;

export interface IntegrationsData {
  catalogsData: IngestionConnectorsCatalogsQuery['response'] | null;
  deploymentData: IngestionConnectorsQuery['response'] | null;
  feedsData: IngestionFeedsData | null;
  formsData: IngestionFeedsFormsData | null;
  refetchFeeds: () => void;
  refetchForms: () => void;
}

interface IntegrationsDataProviderProps {
  children: (data: IntegrationsData) => React.ReactNode;
}

// Loads every data source the current user is granted to see, and passes them
// down to the hero and both tabs. Ungranted sources stay null.
const IntegrationsDataProvider = ({ children }: IntegrationsDataProviderProps) => {
  const isConnectorReader = useGranted([MODULES]);
  const isIngestionReader = useGranted([INGESTION]);
  const isFormReader = useGranted([KNOWLEDGE_KNUPDATE, KNOWLEDGE_KNASKIMPORT]);

  const [catalogsRef, loadCatalogs] = useQueryLoader<IngestionConnectorsCatalogsQuery>(ingestionConnectorsCatalogsQuery);
  const [deploymentRef, loadDeployment] = useQueryLoader<IngestionConnectorsQuery>(ingestionConnectorsQuery);
  const [feedsRef, loadFeeds] = useQueryLoader<IngestionFeedsQuery>(ingestionFeedsQuery);
  const [formsRef, loadForms] = useQueryLoader<IngestionFeedsFormsQuery>(ingestionFeedsFormsQuery);

  useEffect(() => {
    if (isConnectorReader) {
      // fetch once the catalogs and use the cache during runtime
      loadCatalogs({}, { fetchPolicy: 'store-or-network' });
      loadDeployment({}, { fetchPolicy: 'store-and-network' });
    }
    if (isIngestionReader) {
      loadFeeds({ first: FEEDS_PAGE_SIZE }, { fetchPolicy: 'store-and-network' });
    }
    if (isFormReader) {
      loadForms({ first: FEEDS_PAGE_SIZE }, { fetchPolicy: 'store-and-network' });
    }
  }, []);

  // store-and-network: the previous data keeps rendering while the refresh
  // happens in the background, so refetching never suspends the whole page.
  const refetchFeeds = () => {
    if (isIngestionReader) {
      loadFeeds({ first: FEEDS_PAGE_SIZE }, { fetchPolicy: 'store-and-network' });
    }
  };
  const refetchForms = () => {
    if (isFormReader) {
      loadForms({ first: FEEDS_PAGE_SIZE }, { fetchPolicy: 'store-and-network' });
    }
  };

  const renderWithForms = (
    catalogsData: IngestionConnectorsCatalogsQuery['response'] | null,
    deploymentData: IngestionConnectorsQuery['response'] | null,
    feedsData: IngestionFeedsData | null,
  ) => {
    if (formsRef) {
      return (
        <IngestionFeedsForms queryRef={formsRef}>
          {({ data: formsData }) => children({ catalogsData, deploymentData, feedsData, formsData, refetchFeeds, refetchForms })}
        </IngestionFeedsForms>
      );
    }
    return children({ catalogsData, deploymentData, feedsData, formsData: null, refetchFeeds, refetchForms });
  };

  const renderWithFeeds = (
    catalogsData: IngestionConnectorsCatalogsQuery['response'] | null,
    deploymentData: IngestionConnectorsQuery['response'] | null,
  ) => {
    if (feedsRef) {
      return (
        <IngestionFeeds queryRef={feedsRef}>
          {({ data: feedsData }) => renderWithForms(catalogsData, deploymentData, feedsData)}
        </IngestionFeeds>
      );
    }
    return renderWithForms(catalogsData, deploymentData, null);
  };

  const renderWithCatalogs = () => {
    if (catalogsRef && deploymentRef) {
      return (
        <IngestionConnectorsCatalogs queryRef={catalogsRef}>
          {({ data: catalogsData }) => (
            <IngestionConnectors queryRef={deploymentRef}>
              {({ data: deploymentData }) => renderWithFeeds(catalogsData, deploymentData)}
            </IngestionConnectors>
          )}
        </IngestionConnectorsCatalogs>
      );
    }
    return renderWithFeeds(null, null);
  };

  const isLoading = (isConnectorReader && (!catalogsRef || !deploymentRef))
    || (isIngestionReader && !feedsRef)
    || (isFormReader && !formsRef);
  if (isLoading) {
    return <Loader variant={LoaderVariant.container} />;
  }

  return <>{renderWithCatalogs()}</>;
};

interface IntegrationsHeroProps {
  deployedCount: number;
  availableCount: number;
  verifiedCount: number;
  builtInCount: number;
}

const IntegrationsHero = ({ deployedCount, availableCount, verifiedCount, builtInCount }: IntegrationsHeroProps) => {
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
            {t_i18n('Integrations')}
          </Typography>
          <Typography variant="body2" sx={{ color: theme.palette.text.secondary, maxWidth: 640 }}>
            {t_i18n('Browse, deploy and monitor all the integrations feeding your platform with threat intelligence.')}
          </Typography>
          <Stack direction="row" flexWrap="wrap" gap={1} sx={{ marginTop: 2 }}>
            <HeroStatChip icon={RocketLaunchOutlined} value={deployedCount} label={t_i18n('Deployed')} />
            <HeroStatChip icon={ExtensionOutlined} value={availableCount} label={t_i18n('Available connectors')} />
            <HeroStatChip icon={VerifiedOutlined} value={verifiedCount} label={t_i18n('Verified')} />
            <HeroStatChip icon={WidgetsOutlined} value={builtInCount} label={t_i18n('Built-in methods')} />
          </Stack>
        </Box>
        <BrowseMoreButton />
      </Stack>
      <Box sx={{ position: 'relative' }}>
        <IntegrationsStatsStrip />
      </Box>
    </Box>
  );
};

interface IntegrationsComponentProps {
  tab: IntegrationsTab;
  data: IntegrationsData;
}

const IntegrationsComponent = ({ tab, data }: IntegrationsComponentProps) => {
  const { t_i18n } = useFormatter();
  const { hasActiveManagers } = useConnectorManagerStatus();
  const { catalogsData, deploymentData, feedsData, formsData } = data;

  // Hero statistics, computed from every granted data source.
  const { availableCount, verifiedCount } = useMemo(() => {
    let available = 0;
    let verified = 0;
    for (const catalog of catalogsData?.catalogs ?? []) {
      for (const contract of catalog.contracts) {
        try {
          const connector: IngestionConnector = JSON.parse(contract);
          if (connector.manager_supported) {
            available += 1;
            if (connector.verified) verified += 1;
          }
        } catch (_e) {
          // ignored: the available tab notifies parse failures
        }
      }
    }
    return { availableCount: available, verifiedCount: verified };
  }, [catalogsData]);

  // Feed instances register a technical twin connector: excluded from the
  // connector count so deployed integrations are not counted twice.
  const deployedCount = useMemo(() => {
    const feedIds = [
      ...(feedsData?.ingestionRsss?.edges ?? []),
      ...(feedsData?.ingestionTaxiis?.edges ?? []),
      ...(feedsData?.ingestionTaxiiCollections?.edges ?? []),
      ...(feedsData?.ingestionCsvs?.edges ?? []),
      ...(feedsData?.ingestionJsons?.edges ?? []),
      ...(formsData?.forms?.edges ?? []),
    ].flatMap((edge) => (edge?.node ? [edge.node.id] : []));
    const twinConnectorIds = new Set(feedIds.map((id) => connectorIdFromIngestId(id)));
    const connectorCount = (deploymentData?.connectors ?? [])
      .filter((connector) => !twinConnectorIds.has(connector.id))
      .length;
    return connectorCount
      + (feedsData?.synchronizers?.pageInfo?.globalCount ?? 0)
      + (feedsData?.ingestionRsss?.pageInfo?.globalCount ?? 0)
      + (feedsData?.ingestionTaxiis?.pageInfo?.globalCount ?? 0)
      + (feedsData?.ingestionTaxiiCollections?.pageInfo?.globalCount ?? 0)
      + (feedsData?.ingestionCsvs?.pageInfo?.globalCount ?? 0)
      + (feedsData?.ingestionJsons?.pageInfo?.globalCount ?? 0)
      + (formsData?.forms?.pageInfo?.globalCount ?? 0);
  }, [deploymentData, feedsData, formsData]);

  return (
    <div data-testid="integrations-page">
      <PageContainer withGap>
        {/* The active tab is enough context: the breadcrumb only carries the
            section name (detail pages do include the originating tab). */}
        <Breadcrumbs
          elements={[{ label: t_i18n('Integrations'), current: true }]}
          noMargin
        />
        <ConnectorDeploymentBanner hasActiveManagers={hasActiveManagers} />

        <IntegrationsHero
          deployedCount={deployedCount}
          availableCount={availableCount}
          verifiedCount={verifiedCount}
          builtInCount={BUILT_IN_INTEGRATIONS.length}
        />

        <Tabs value={tab}>
          <Tab
            label={t_i18n('Deployed')}
            value="deployed"
            component={Link}
            to="/dashboard/integrations/deployed"
            data-testid="integrations-tab-deployed"
          />
          <Tab
            label={t_i18n('Available')}
            value="available"
            component={Link}
            to="/dashboard/integrations/available"
            data-testid="integrations-tab-available"
          />
        </Tabs>

        {tab === 'deployed' ? (
          <IntegrationsDeployed data={data} />
        ) : (
          <IntegrationsAvailable data={data} />
        )}
      </PageContainer>
    </div>
  );
};

const Integrations = () => {
  const { tab } = useParams();
  const { t_i18n } = useFormatter();
  const { setTitle } = useConnectedDocumentModifier();
  setTitle(t_i18n('Integrations'));

  if (tab !== 'deployed' && tab !== 'available') {
    return <Navigate to="/dashboard/integrations/deployed" replace={true} />;
  }

  return (
    <Suspense fallback={<Loader variant={LoaderVariant.container} />}>
      <ConnectorManagerStatusProvider>
        <IntegrationsDataProvider>
          {(data) => <IntegrationsComponent tab={tab} data={data} />}
        </IntegrationsDataProvider>
      </ConnectorManagerStatusProvider>
    </Suspense>
  );
};

export default Integrations;
