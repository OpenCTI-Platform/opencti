import React, { Suspense } from 'react';
import { graphql, useLazyLoadQuery } from 'react-relay';
import { Link } from 'react-router';
import { useTheme } from '@mui/styles';
import { Text } from '@filigran/design-system';
import Card from '../../../components/common/card/Card';
import Loader, { LoaderVariant } from '../../../components/Loader';
import { useFormatter } from '../../../components/i18n';
import type { Theme } from '../../../components/Theme';
import { PATH_HUNT } from '../common/routes/paths';
import { HuntRunStatusChip, HuntVerdictChip } from './HuntChips';
import { HUNT_DOCS, HUNT_RUN_ENTITY_TYPE, huntRunTriggerLabel } from './hunt-utils';
import { HuntHelp } from './HuntLearnMore';
import { HuntLatestRunsQuery, HuntLatestRunsQuery$variables } from './__generated__/HuntLatestRunsQuery.graphql';

const LATEST_RUNS_COUNT = 6;

const huntLatestRunsQuery = graphql`
  query HuntLatestRunsQuery($filters: FilterGroup, $count: Int!) {
    huntRuns(first: $count, orderBy: created_at, orderMode: desc, filters: $filters) {
      edges {
        node {
          id
          hunt_run_status
          hunt_run_trigger
          hunt_run_mode
          hits_count
          verdict
          created_at
          connector_name
          securityPlatform {
            id
            name
          }
        }
      }
    }
  }
`;

interface HuntLatestRunsProps {
  huntId: string;
  // The edit right of the hunt page: the next step named to a user who can only view the hunt is not theirs to take
  canEdit: boolean;
}

const LatestRunsList = ({ huntId, canEdit }: HuntLatestRunsProps) => {
  const theme = useTheme<Theme>();
  const { t_i18n, fldt } = useFormatter();
  const filters: HuntLatestRunsQuery$variables['filters'] = {
    mode: 'and',
    filters: [
      { key: ['entity_type'], values: [HUNT_RUN_ENTITY_TYPE], operator: 'eq', mode: 'or' },
      { key: ['hunt_id'], values: [huntId], operator: 'eq', mode: 'or' },
    ],
    filterGroups: [],
  };
  const { huntRuns } = useLazyLoadQuery<HuntLatestRunsQuery>(
    huntLatestRunsQuery,
    { filters, count: LATEST_RUNS_COUNT },
    { fetchPolicy: 'store-and-network' },
  );
  const runs = (huntRuns?.edges ?? []).map((edge) => edge.node);
  if (runs.length === 0) {
    return (
      <div data-testid="hunt-latest-runs-empty">
        <Text variant="content-compact">{t_i18n('This hunt has not run yet')}</Text>
        <Text variant="content-caption" style={{ display: 'block', marginTop: theme.spacing(0.5), color: theme.palette.text.secondary }}>
          <HuntHelp
            text={canEdit
              ? t_i18n('Next step: Run now at the top of the page, or Activate it to run on its schedule. Each run appears here with its verdict.')
              : t_i18n('Each run appears here with its verdict once a user who can edit the hunt runs it or activates it.')}
            href={HUNT_DOCS.runHunt}
          />
        </Text>
      </div>
    );
  }
  return (
    <ul style={{ listStyle: 'none', margin: 0, padding: 0 }} data-testid="hunt-latest-runs">
      {runs.map((run) => (
        <li key={run.id} style={{ borderBottom: `1px solid ${theme.palette.divider}` }}>
          <Link
            to={`${PATH_HUNT(huntId)}/runs/${run.id}`}
            style={{ display: 'flex', alignItems: 'center', gap: theme.spacing(1.5), padding: theme.spacing(1, 0), color: 'inherit', textDecoration: 'none' }}
          >
            <span style={{ minWidth: 150 }}><Text variant="content-compact">{fldt(run.created_at)}</Text></span>
            <HuntRunStatusChip value={run.hunt_run_status} />
            <span style={{ flex: 1, minWidth: 0, display: 'flex', flexDirection: 'column' }}>
              <span style={{ overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
                <Text variant="content-compact">{run.securityPlatform?.name ?? run.connector_name ?? t_i18n('Internet')}</Text>
              </span>
              <Text variant="content-caption">{t_i18n(huntRunTriggerLabel(run.hunt_run_trigger))}</Text>
            </span>
            {run.hunt_run_mode === 'preview' ? (
              <Text variant="content-caption">{t_i18n('Translation preview')}</Text>
            ) : (
              <>
                <Text variant="content-compact">{t_i18n('{count, plural, =0 {No hit} one {# hit} other {# hits}}', { values: { count: run.hits_count ?? 0 } })}</Text>
                <HuntVerdictChip value={run.verdict} />
              </>
            )}
          </Link>
        </li>
      ))}
    </ul>
  );
};

const HuntLatestRuns = ({ huntId, canEdit }: HuntLatestRunsProps) => {
  const { t_i18n } = useFormatter();
  return (
    <Card title={t_i18n('Latest runs')} action={<Link to={`${PATH_HUNT(huntId)}/runs`}>{t_i18n('View all')}</Link>}>
      <Suspense fallback={<Loader variant={LoaderVariant.inElement} />}>
        <LatestRunsList huntId={huntId} canEdit={canEdit} />
      </Suspense>
    </Card>
  );
};

export default HuntLatestRuns;
