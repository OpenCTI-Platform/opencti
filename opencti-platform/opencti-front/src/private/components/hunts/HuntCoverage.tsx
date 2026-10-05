import React, { Suspense } from 'react';
import { graphql, useFragment, useLazyLoadQuery } from 'react-relay';
import { Link } from 'react-router';
import Grid from '@mui/material/Grid';
import { useTheme } from '@mui/styles';
import { Text } from '@filigran/design-system';
import Button from '@common/button/Button';
import Card from '../../../components/common/card/Card';
import Security from '../../../utils/Security';
import { KNOWLEDGE_KNUPDATE } from '../../../utils/hooks/useGranted';
import Loader, { LoaderVariant } from '../../../components/Loader';
import { useFormatter } from '../../../components/i18n';
import type { Theme } from '../../../components/Theme';
import { PATH_ATTACK_PATTERN, PATH_HUNT, PATH_SECURITY_COVERAGE, PATH_SECURITY_COVERAGES } from '../common/routes/paths';
import { HuntRunStatusChip, HuntTechniqueValidationChip } from './HuntChips';
import { HUNT_RUN_ENTITY_TYPE, type HuntTechniqueValidationStatus } from './hunt-utils';
import { HuntCoverage_hunt$key } from './__generated__/HuntCoverage_hunt.graphql';
import { HuntCoverageEmulationRunsQuery, HuntCoverageEmulationRunsQuery$variables } from './__generated__/HuntCoverageEmulationRunsQuery.graphql';

// Latest runs only: the status of each technique comes from Hunt.techniqueValidations, computed over every run
const EMULATION_RUNS_COUNT = 50;

const huntCoverageFragment = graphql`
  fragment HuntCoverage_hunt on Hunt {
    id
    huntTechniques {
      id
      name
      x_mitre_id
    }
    techniqueValidations {
      technique_id
      status
    }
  }
`;

interface HuntCoverageHunt {
  id: string;
  huntTechniques?: ReadonlyArray<{ id: string; name: string; x_mitre_id?: string | null }> | null;
  techniqueValidations: ReadonlyArray<{ technique_id: string; status: string }>;
}

const VALIDATION_STATUSES: HuntTechniqueValidationStatus[] = ['validated', 'not_detected', 'in_progress', 'not_validated'];

const toValidationStatus = (status: string | undefined): HuntTechniqueValidationStatus => {
  return VALIDATION_STATUSES.find((known) => known === status) ?? 'not_validated';
};

const huntCoverageEmulationRunsQuery = graphql`
  query HuntCoverageEmulationRunsQuery($filters: FilterGroup, $count: Int!) {
    huntRuns(first: $count, orderBy: created_at, orderMode: desc, filters: $filters) {
      edges {
        node {
          id
          technique_id
          hunt_run_status
          hits_count
          security_coverage_id
          aev_inject_id
          completed_at
          created_at
          securityPlatform {
            id
            name
          }
        }
      }
    }
  }
`;

const HuntCoverageComponent = ({ hunt }: { hunt: HuntCoverageHunt }) => {
  const theme = useTheme<Theme>();
  const { t_i18n, fldt } = useFormatter();
  const filters: HuntCoverageEmulationRunsQuery$variables['filters'] = {
    mode: 'and',
    filters: [
      { key: ['entity_type'], values: [HUNT_RUN_ENTITY_TYPE], operator: 'eq', mode: 'or' },
      { key: ['hunt_id'], values: [hunt.id], operator: 'eq', mode: 'or' },
      { key: ['hunt_run_trigger'], values: ['emulation'], operator: 'eq', mode: 'or' },
    ],
    filterGroups: [],
  };
  const { huntRuns } = useLazyLoadQuery<HuntCoverageEmulationRunsQuery>(
    huntCoverageEmulationRunsQuery,
    { filters, count: EMULATION_RUNS_COUNT },
    { fetchPolicy: 'store-and-network' },
  );
  const emulationRuns = (huntRuns?.edges ?? []).map(({ node }) => node);
  const techniques = [...(hunt.huntTechniques ?? [])].sort((a, b) => (a.x_mitre_id ?? a.name).localeCompare(b.x_mitre_id ?? b.name));
  const coverageIds = Array.from(new Set(emulationRuns.map((run) => run.security_coverage_id).filter((id): id is string => !!id)));
  const statusByTechnique = new Map(hunt.techniqueValidations.map((validation) => [validation.technique_id, toValidationStatus(validation.status)]));
  const statusOf = (techniqueId: string) => statusByTechnique.get(techniqueId) ?? 'not_validated';
  const validated = techniques.filter((technique) => statusOf(technique.id) === 'validated').length;

  return (
    <Grid container spacing={3}>
      <Grid item xs={12} md={7}>
        <Card title={t_i18n('Covered techniques')}>
          {techniques.length === 0 ? (
            <Text variant="content-compact">{t_i18n('This hunt is not linked to any attack pattern')}</Text>
          ) : (
            <>
              <Text variant="content-caption" style={{ display: 'block', marginBottom: theme.spacing(1) }}>
                {t_i18n('{validated} of {total} techniques have a detection proven by an emulation', { values: { validated, total: techniques.length } })}
              </Text>
              <ul style={{ listStyle: 'none', margin: 0, padding: 0 }} data-testid="hunt-coverage-techniques">
                {techniques.map((technique) => {
                  const status = statusOf(technique.id);
                  return (
                    <li key={technique.id} style={{ display: 'flex', alignItems: 'center', gap: theme.spacing(1), padding: theme.spacing(1, 0), borderBottom: `1px solid ${theme.palette.divider}` }}>
                      <Link to={PATH_ATTACK_PATTERN(technique.id)} style={{ flex: 1, minWidth: 0 }}>
                        {technique.x_mitre_id ? `[${technique.x_mitre_id}] ${technique.name}` : technique.name}
                      </Link>
                      <HuntTechniqueValidationChip status={status} />
                    </li>
                  );
                })}
              </ul>
            </>
          )}
        </Card>
      </Grid>
      <Grid item xs={12} md={5}>
        <Card title={t_i18n('Emulation validations')}>
          {emulationRuns.length === 0 ? (
            <>
              <Text variant="content-compact">
                {t_i18n('No emulation has validated this hunt yet. OpenAEV validates a hunt when a Security Coverage simulation exercises one of its techniques.')}
              </Text>
              <Security needs={[KNOWLEDGE_KNUPDATE]}>
                <Button
                  variant="secondary"
                  size="small"
                  component={Link}
                  to={PATH_SECURITY_COVERAGES}
                  style={{ marginTop: theme.spacing(1.5) }}
                  data-testid="hunt-coverage-run-simulation"
                >
                  {t_i18n('Run a Security Coverage simulation')}
                </Button>
              </Security>
            </>
          ) : (
            <ul style={{ listStyle: 'none', margin: 0, padding: 0 }} data-testid="hunt-coverage-emulations">
              {emulationRuns.map((run) => {
                const technique = techniques.find((item) => item.id === run.technique_id);
                return (
                  <li key={run.id} style={{ padding: theme.spacing(1, 0), borderBottom: `1px solid ${theme.palette.divider}` }}>
                    <div style={{ display: 'flex', alignItems: 'center', gap: theme.spacing(1), flexWrap: 'wrap' }}>
                      <Link to={`${PATH_HUNT(hunt.id)}/runs/${run.id}`}>{fldt(run.completed_at ?? run.created_at)}</Link>
                      <HuntRunStatusChip value={run.hunt_run_status} />
                      <Text variant="content-compact">
                        {t_i18n('{count, plural, =0 {No hit} one {# hit} other {# hits}}', { values: { count: run.hits_count ?? 0 } })}
                      </Text>
                    </div>
                    <Text variant="content-caption">
                      {[technique ? (technique.x_mitre_id ?? technique.name) : null, run.securityPlatform?.name].filter(Boolean).join(' - ')}
                    </Text>
                  </li>
                );
              })}
            </ul>
          )}
          {coverageIds.length > 0 && (
            <div style={{ marginTop: theme.spacing(2) }} data-testid="hunt-coverage-links">
              <Text variant="content-compact-bold">{t_i18n('Security coverages')}</Text>
              <ul style={{ margin: 0, paddingLeft: theme.spacing(2) }}>
                {coverageIds.map((coverageId) => (
                  <li key={coverageId}>
                    <Link to={PATH_SECURITY_COVERAGE(coverageId)}>{t_i18n('Open the security coverage')}</Link>
                  </li>
                ))}
              </ul>
            </div>
          )}
        </Card>
      </Grid>
    </Grid>
  );
};

const HuntCoverage = ({ data }: { data: HuntCoverage_hunt$key }) => {
  const hunt = useFragment(huntCoverageFragment, data);
  return (
    <div data-testid="hunt-coverage-page">
      <Suspense fallback={<Loader variant={LoaderVariant.inElement} />}>
        <HuntCoverageComponent hunt={hunt} />
      </Suspense>
    </div>
  );
};

export default HuntCoverage;
