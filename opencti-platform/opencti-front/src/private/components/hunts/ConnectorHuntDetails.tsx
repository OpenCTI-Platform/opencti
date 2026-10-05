import React, { Suspense } from 'react';
import { graphql, useFragment, useLazyLoadQuery } from 'react-relay';
import { Link } from 'react-router';
import { useTheme } from '@mui/styles';
import { Text } from '@filigran/design-system';
import Card from '../../../components/common/card/Card';
import Label from '../../../components/common/label/Label';
import Loader, { LoaderVariant } from '../../../components/Loader';
import { useFormatter } from '../../../components/i18n';
import type { Theme } from '../../../components/Theme';
import useAuth from '../../../utils/hooks/useAuth';
import { isGrantedTo, KNOWLEDGE } from '../../../utils/hooks/useGranted';
import { useHiddenEntities } from '../../../utils/hooks/useEntitySettings';
import { PATH_HUNT, PATH_HUNTS, PATH_SECURITY_PLATFORM } from '../common/routes/paths';
import { HuntRunStatusChip, HuntVerdictChip } from './HuntChips';
import { HuntConnectorRequiredPermissions, HuntConnectorTestConnection } from './HuntConnectorSetup';
import { HUNT_ENTITY_TYPE, HUNT_RUN_ENTITY_TYPE, huntMessageText, huntPlatformLabel, huntQueryLanguageLabel, huntRunTriggerLabel } from './hunt-utils';
import type { ConnectorHuntDetails_hunt$key } from './__generated__/ConnectorHuntDetails_hunt.graphql';
import type { ConnectorHuntDetailsRunsQuery, ConnectorHuntDetailsRunsQuery$variables } from './__generated__/ConnectorHuntDetailsRunsQuery.graphql';

const CONNECTOR_LATEST_RUNS_COUNT = 5;

const connectorHuntDetailsFragment = graphql`
  fragment ConnectorHuntDetails_hunt on HuntConnector {
    active
    platform
    languages
    supports_preview
    supports_indicators
    max_concurrent_runs
    documentation_url
    required_permissions {
      name
      purpose
    }
    connection_check {
      id
      status
      requested_at
      checked_at
      checks {
        name
        ok
        message
      }
    }
    securityPlatform {
      id
      name
    }
  }
`;

const connectorHuntDetailsRunsQuery = graphql`
  query ConnectorHuntDetailsRunsQuery($filters: FilterGroup, $count: Int!) {
    huntRuns(first: $count, orderBy: created_at, orderMode: desc, filters: $filters) {
      edges {
        node {
          id
          hunt_id
          hunt_run_status
          hunt_run_trigger
          hunt_run_mode
          hits_count
          verdict
          created_at
          hunt_deleted
          hunt {
            name
          }
          queue_reason {
            template
            values {
              name
              value
            }
          }
        }
      }
    }
  }
`;

export const ConnectorLatestHuntRuns = ({ connectorId }: { connectorId: string }) => {
  const theme = useTheme<Theme>();
  const { t_i18n, fldt } = useFormatter();
  const filters: ConnectorHuntDetailsRunsQuery$variables['filters'] = {
    mode: 'and',
    filters: [
      { key: ['entity_type'], values: [HUNT_RUN_ENTITY_TYPE], operator: 'eq', mode: 'or' },
      { key: ['connector_id'], values: [connectorId], operator: 'eq', mode: 'or' },
    ],
    filterGroups: [],
  };
  const { huntRuns } = useLazyLoadQuery<ConnectorHuntDetailsRunsQuery>(
    connectorHuntDetailsRunsQuery,
    { filters, count: CONNECTOR_LATEST_RUNS_COUNT },
    { fetchPolicy: 'store-and-network' },
  );
  const runs = (huntRuns?.edges ?? []).map((edge) => edge.node);
  if (runs.length === 0) {
    return <Text variant="content-compact">{t_i18n('This connector has not run a hunt yet')}</Text>;
  }
  return (
    <ul style={{ listStyle: 'none', margin: 0, padding: 0 }} data-testid="connector-hunt-runs">
      {runs.map((run) => {
        const rowStyle = { display: 'flex', alignItems: 'center', gap: theme.spacing(1.5), padding: theme.spacing(1, 0), color: 'inherit', textDecoration: 'none' };
        const row = (
          <>
            <HuntRunStatusChip value={run.hunt_run_status} />
            <span style={{ flex: 1, minWidth: 0, display: 'flex', flexDirection: 'column' }}>
              <span style={{ overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }} title={run.hunt?.name ?? undefined}>
                <Text variant="content-compact">{run.hunt?.name ?? t_i18n(run.hunt_deleted ? 'Deleted hunt' : 'Restricted hunt')}</Text>
              </span>
              <Text variant="content-caption">{`${fldt(run.created_at)} - ${t_i18n(huntRunTriggerLabel(run.hunt_run_trigger))}`}</Text>
              {run.queue_reason && (
                <Text variant="content-caption" style={{ color: theme.palette.text.secondary }} data-testid="connector-hunt-run-queue-reason">
                  {huntMessageText(run.queue_reason, t_i18n)}
                </Text>
              )}
            </span>
            {run.hunt_run_mode === 'preview' ? (
              <Text variant="content-caption">{t_i18n('Translation preview')}</Text>
            ) : (
              <>
                <Text variant="content-compact">{t_i18n('{count, plural, =0 {No hit} one {# hit} other {# hits}}', { values: { count: run.hits_count ?? 0 } })}</Text>
                <HuntVerdictChip value={run.verdict} />
              </>
            )}
          </>
        );
        return (
          <li key={run.id} style={{ borderBottom: `1px solid ${theme.palette.divider}` }} data-testid="connector-hunt-run">
            {run.hunt_deleted
              ? <div style={rowStyle}>{row}</div>
              : <Link to={`${PATH_HUNT(run.hunt_id)}/runs/${run.id}`} style={rowStyle}>{row}</Link>}
          </li>
        );
      })}
    </ul>
  );
};

interface ConnectorHuntDetailsProps {
  connectorId: string;
  data: ConnectorHuntDetails_hunt$key;
}

/**
 * Hunted platform of an INTERNAL_HUNT connector, shown on its connector page.
 * The latest runs and the link to Defense > Hunts only show to readers who can see the Hunts area.
 */
const ConnectorHuntDetails = ({ connectorId, data }: ConnectorHuntDetailsProps) => {
  const theme = useTheme<Theme>();
  const { t_i18n, n } = useFormatter();
  const { me } = useAuth();
  const hiddenEntities = useHiddenEntities();
  const hunt = useFragment(connectorHuntDetailsFragment, data);
  const canSeeHunts = isGrantedTo(me, [KNOWLEDGE]) && !hiddenEntities.includes(HUNT_ENTITY_TYPE);
  const languages = hunt.languages.map((language) => huntQueryLanguageLabel(language, t_i18n)).filter((label) => label.length > 0);
  return (
    <Card
      title={t_i18n('Hunted platform')}
      action={canSeeHunts ? <Link to={PATH_HUNTS}>{t_i18n('Open Hunts')}</Link> : undefined}
    >
      <div
        style={{ display: 'grid', gridTemplateColumns: 'repeat(2, minmax(0, 1fr))', gap: theme.spacing(2) }}
        data-testid="connector-hunt-details"
      >
        <div>
          <Label>{t_i18n('Platform')}</Label>
          <Text variant="content-compact">{huntPlatformLabel(hunt.platform, t_i18n)}</Text>
        </div>
        <div>
          <Label>{t_i18n('Security platform')}</Label>
          {hunt.securityPlatform ? (
            <Link to={PATH_SECURITY_PLATFORM(hunt.securityPlatform.id)}>{hunt.securityPlatform.name}</Link>
          ) : (
            <Text variant="content-compact">{t_i18n('None, internet hunts have no security platform')}</Text>
          )}
        </div>
        <div>
          <Label>{t_i18n('Query languages')}</Label>
          <Text variant="content-compact">{languages.length > 0 ? languages.join(', ') : t_i18n('Sigma translation only')}</Text>
        </div>
        <div>
          <Label>{t_i18n('Maximum concurrent runs')}</Label>
          <Text variant="content-compact">
            {hunt.max_concurrent_runs && hunt.max_concurrent_runs > 0 ? n(hunt.max_concurrent_runs) : t_i18n('No limit set by the connector')}
          </Text>
        </div>
        <div>
          <Label>{t_i18n('Translation preview')}</Label>
          <Text variant="content-compact">{hunt.supports_preview ? t_i18n('Supported') : t_i18n('Not supported')}</Text>
        </div>
        <div>
          <Label>{t_i18n('Indicator hunts')}</Label>
          <Text variant="content-compact">{hunt.supports_indicators ? t_i18n('Supported') : t_i18n('Not supported')}</Text>
        </div>
      </div>
      <div style={{ marginTop: theme.spacing(2), display: 'flex', flexDirection: 'column', gap: theme.spacing(2) }}>
        <HuntConnectorRequiredPermissions
          permissions={hunt.required_permissions}
          documentationUrl={hunt.documentation_url}
          defaultOpen={hunt.connection_check?.status !== 'passed'}
        />
        <HuntConnectorTestConnection connectorId={connectorId} active={hunt.active} check={hunt.connection_check} />
      </div>
      {canSeeHunts && (
        <div style={{ marginTop: theme.spacing(2) }}>
          <Label>{t_i18n('Latest hunt runs')}</Label>
          <Suspense fallback={<Loader variant={LoaderVariant.inElement} />}>
            <ConnectorLatestHuntRuns connectorId={connectorId} />
          </Suspense>
        </div>
      )}
    </Card>
  );
};

export default ConnectorHuntDetails;
