import React, { Suspense, useCallback, useEffect, useMemo, useState } from 'react';
import { Link } from 'react-router';
import { Box, Typography } from '@mui/material';
import { useTheme } from '@mui/material/styles';
import { useQueryLoader } from 'react-relay';
import { ErrorOutlineOutlined, SettingsOutlined, type SvgIconComponent, WarningAmberOutlined } from '@mui/icons-material';
import { interval } from 'rxjs';
import Button from '@common/button/Button';
import ConnectorsList, { connectorsListQuery } from '@components/data/connectors/ConnectorsList';
import ConnectorsLogos, { connectorsLogosQuery } from '@components/data/connectors/ConnectorsLogos';
import ConnectorsState, { connectorsStateQuery } from '@components/data/connectors/ConnectorsState';
import { ConnectorsListQuery } from '@components/data/connectors/__generated__/ConnectorsListQuery.graphql';
import { ConnectorsLogosQuery } from '@components/data/connectors/__generated__/ConnectorsLogosQuery.graphql';
import { ConnectorsStateQuery } from '@components/data/connectors/__generated__/ConnectorsStateQuery.graphql';
import DeployedIntegrationLine, { DeployedIntegrationLinesHeader } from '@components/integrations/deployed/DeployedIntegrationLine';
import useDeployedIntegrations, { type DeployedIntegrationItem } from '@components/integrations/deployed/useDeployedIntegrations';
import { MarketplaceSectionHeader } from '@components/integrations/components/MarketplaceUi';
import { IntegrationsData } from '@components/integrations/Integrations';
import { useFormatter } from '../../../../components/i18n';
import Loader, { LoaderVariant } from '../../../../components/Loader';
import useGranted, { MODULES } from '../../../../utils/hooks/useGranted';
import { FIVE_SECONDS } from '../../../../utils/Time';
import { hasConfigurationFinding } from '../../../../utils/IngestionHealth';
import { paperBg, paperBorder } from '../paperSurface';

const interval$ = interval(FIVE_SECONDS);

// One bucket per reason someone would act, ordered by how soon they should.
// A source appears in exactly one — the most urgent that applies — because a
// list that repeats the same integration three times is a list nobody trusts.
type AttentionBucket = 'critical' | 'degraded' | 'misconfigured';

const bucketFor = (item: DeployedIntegrationItem): AttentionBucket | null => {
  const status = item.health?.status;
  if (status === 'critical') return 'critical';
  if (status === 'degraded') return 'degraded';
  // Configuration is its own axis, so a perfectly healthy source can land here.
  // Driven by the findings rather than by configuration_status, for the same
  // reason the row marker is: the checks are what say something is wrong.
  if (hasConfigurationFinding(item.health) || (item.health?.configuration_status ?? 'ok') !== 'ok') {
    return 'misconfigured';
  }
  return null;
};

// `stopped`, `idle` and `unknown` are deliberately absent. Someone switched it
// off, it is not due yet, or nothing has been observed — none of those is a
// problem, and putting them here is how a triage screen becomes noise people
// learn to scroll past.
const BUCKET_ORDER: AttentionBucket[] = ['critical', 'degraded', 'misconfigured'];

interface IntegrationsAttentionContentProps {
  data: IntegrationsData;
  connectorsListData: ConnectorsListQuery['response'] | null;
  connectorsStateData: ConnectorsStateQuery['response'] | null;
  logosBySlug: Map<string, string>;
  onConnectorsChange: () => void;
}

const IntegrationsAttentionContent = ({
  data,
  connectorsListData,
  connectorsStateData,
  logosBySlug,
  onConnectorsChange,
}: IntegrationsAttentionContentProps) => {
  const { t_i18n } = useFormatter();
  const theme = useTheme();
  const { feedsData, formsData } = data;

  // The same list the Deployed tab builds, from the same queries — this tab is
  // a view over it, not a second source of truth that could disagree.
  const items = useDeployedIntegrations({
    connectorsListData,
    connectorsStateData,
    feedsData,
    formsData,
    logosBySlug,
  });

  const buckets = useMemo(() => {
    const grouped: Record<AttentionBucket, DeployedIntegrationItem[]> = {
      critical: [],
      degraded: [],
      misconfigured: [],
    };
    items.forEach((item) => {
      const bucket = bucketFor(item);
      if (bucket) {
        grouped[bucket].push(item);
      }
    });
    BUCKET_ORDER.forEach((bucket) => {
      grouped[bucket].sort((a, b) => a.name.localeCompare(b.name));
    });
    return grouped;
  }, [items]);

  const total = BUCKET_ORDER.reduce((sum, bucket) => sum + buckets[bucket].length, 0);

  const bucketLabel: Record<AttentionBucket, string> = {
    critical: t_i18n('Not working'),
    degraded: t_i18n('Underperforming'),
    misconfigured: t_i18n('Misconfigured'),
  };

  // MarketplaceSectionHeader takes a required icon; the three are distinct at a
  // glance so the sections stay tellable apart when scrolled past.
  const bucketIcon: Record<AttentionBucket, SvgIconComponent> = {
    critical: ErrorOutlineOutlined,
    degraded: WarningAmberOutlined,
    misconfigured: SettingsOutlined,
  };

  // What each bucket means, in the terms someone triaging would use. Worth the
  // line: "degraded" on its own does not tell anyone whether to act now.
  const bucketHint: Record<AttentionBucket, string> = {
    critical: t_i18n('Failed, crashed, or nothing is consuming the queue.'),
    degraded: t_i18n('Still running, but late or repeatedly bringing nothing in.'),
    misconfigured: t_i18n('Ingesting, but configured in a way that needs fixing.'),
  };

  if (total === 0) {
    return (
      <Box
        sx={{
          borderRadius: 1,
          border: `1px solid ${paperBorder(theme)}`,
          backgroundColor: paperBg(theme),
          padding: 6,
          textAlign: 'center',
        }}
      >
        <Typography variant="h6" sx={{ marginBottom: 1 }}>
          {t_i18n('Everything is healthy')}
        </Typography>
        <Typography variant="body2" sx={{ color: theme.palette.text.secondary, marginBottom: 2 }}>
          {t_i18n('No integration needs attention right now.')}
        </Typography>
        <Button component={Link} to="/dashboard/integrations/deployed" variant="outlined">
          {t_i18n('View all deployed integrations')}
        </Button>
      </Box>
    );
  }

  return (
    <Box sx={{ display: 'flex', flexDirection: 'column', gap: 3 }}>
      {BUCKET_ORDER.filter((bucket) => buckets[bucket].length > 0).map((bucket) => (
        <Box key={bucket}>
          <MarketplaceSectionHeader
            icon={bucketIcon[bucket]}
            label={bucketLabel[bucket]}
            count={buckets[bucket].length}
          />
          <Typography variant="body2" sx={{ color: theme.palette.text.secondary, marginBottom: 1 }}>
            {bucketHint[bucket]}
          </Typography>
          <Box
            sx={{
              borderRadius: 1,
              border: `1px solid ${paperBorder(theme)}`,
              backgroundColor: paperBg(theme),
              overflow: 'hidden',
            }}
          >
            <DeployedIntegrationLinesHeader />
            {buckets[bucket].map((item) => (
              <DeployedIntegrationLine
                key={item.id}
                item={item}
                onChange={onConnectorsChange}
              />
            ))}
          </Box>
        </Box>
      ))}
    </Box>
  );
};

interface IntegrationsAttentionProps {
  data: IntegrationsData;
}

// Deliberately mirrors IntegrationsDeployed's loading: the same three queries,
// the same five-second refresh. Anything else and the two tabs would show
// different answers for the same source depending on which you opened first.
const IntegrationsAttention = ({ data }: IntegrationsAttentionProps) => {
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
    const subscription = interval$.subscribe(() => {
      loadConnectorsState({}, { fetchPolicy: 'store-and-network' });
    });
    return () => subscription.unsubscribe();
  }, []);

  const onConnectorsChange = useCallback(() => {
    if (!isConnectorReader) return;
    loadConnectorsList({}, { fetchPolicy: 'store-and-network' });
    loadConnectorsState({}, { fetchPolicy: 'store-and-network' });
  }, [isConnectorReader]);

  const renderContent = (
    connectorsListData: ConnectorsListQuery['response'] | null,
    connectorsStateData: ConnectorsStateQuery['response'] | null,
  ) => (
    <IntegrationsAttentionContent
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
                      <ConnectorsLogos queryRef={connectorsLogosRef} onLoaded={setLogosBySlug} />
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

export { bucketFor };
export default IntegrationsAttention;
