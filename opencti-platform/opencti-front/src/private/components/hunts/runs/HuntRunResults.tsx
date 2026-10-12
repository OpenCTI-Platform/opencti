import React from 'react';
import { graphql, useFragment, usePaginationFragment } from 'react-relay';
import { useTheme } from '@mui/styles';
import { Text } from '@filigran/design-system';
import Button from '@common/button/Button';
import Card from '../../../../components/common/card/Card';
import ItemIcon from '../../../../components/ItemIcon';
import { useFormatter } from '../../../../components/i18n';
import type { Theme } from '../../../../components/Theme';
import { resolveLink } from '../../../../utils/Entity';
import { huntExtractsObservables } from '../hunt-utils';
import HuntRunTable, { HuntRunCut, HuntRunDateCell, HuntRunSortValue, huntRunTextCell, sortHuntRunRows, useHuntRunTableSort } from './HuntRunTable';
import { HuntRunResultsPaginationQuery } from './__generated__/HuntRunResultsPaginationQuery.graphql';
import { HuntRunResults_data$data, HuntRunResults_data$key } from './__generated__/HuntRunResults_data.graphql';

export const HUNT_RUN_RESULTS_PAGE_SIZE = 25;

export const huntRunResultsFragment = graphql`
  fragment HuntRunResults_data on Query
  @refetchable(queryName: "HuntRunResultsPaginationQuery")
  @argumentDefinitions(
    id: { type: "String!" }
    count: { type: "Int", defaultValue: 25 }
    cursor: { type: "ID" }
  ) {
    huntRun(id: $id) {
      hunt_run_status
      hits_count
      incident_id
      incident_continued
      sightings_created_count
      security_platform_id
      hunt {
        id
        hunt_type
      }
      results_summary {
        sightings
        observed_data
        observables
        others
      }
      results(first: $count, after: $cursor) @connection(key: "HuntRunResults_results") {
        pageInfo {
          globalCount
          hasNextPage
          endCursor
        }
        edges {
          node {
            ... on BasicObject {
              id
              entity_type
            }
            ... on StixObject {
              representative {
                main
              }
              created_at
              updated_at
            }
            ... on StixRelationship {
              representative {
                main
              }
              created_at
              updated_at
            }
            ... on StixCoreRelationship {
              from {
                ... on BasicObject {
                  id
                  entity_type
                }
              }
            }
          }
        }
      }
    }
  }
`;

interface ResultNode {
  readonly id?: string;
  readonly entity_type?: string;
  readonly from?: { readonly id?: string; readonly entity_type?: string } | null;
}

/**
 * The page of a result: its own route, or for a relationship without one, the relationship page under its source
 * entity. Null when neither exists, the result is then shown without a link.
 */
export const huntRunResultLink = (result: ResultNode): string | null => {
  if (!result.id) {
    return null;
  }
  const route = resolveLink(result.entity_type);
  if (route) {
    return `${route}/${result.id}`;
  }
  const fromRoute = result.from?.id && result.from.entity_type ? resolveLink(result.from.entity_type) : null;
  return fromRoute ? `${fromRoute}/${result.from?.id}/knowledge/relations/${result.id}` : null;
};

type HuntRunTranslate = (message: string, options?: { values: Record<string, string | number> }) => string;

interface HuntRunKnowledgeInput {
  readonly hunt_run_status?: string | null;
  readonly hits_count?: number | null;
  readonly incident_id?: string | null;
  readonly incident_continued?: boolean | null;
  readonly sightings_created_count?: number | null;
  readonly security_platform_id?: string | null;
  readonly hunt?: { readonly hunt_type?: string | null } | null;
  readonly results_summary?: { readonly sightings: number; readonly observed_data: number; readonly observables: number; readonly others: number } | null;
}

/**
 * What a run produced, in one line, and why a completed run with hits has no sighting or no observable: null while a
 * run has produced nothing yet. A hunt keeps one sighting per sighted object and platform: a run creates it the first
 * time and updates it afterwards; a run whose hits joined an incident still open says so.
 */
export const huntRunKnowledge = (run: HuntRunKnowledgeInput, t_i18n: HuntRunTranslate) => {
  const summary = run.results_summary ?? { sightings: 0, observed_data: 0, observables: 0, others: 0 };
  const count = (message: string, value: number) => (value > 0 ? t_i18n(message, { values: { count: value } }) : null);
  const createdSightings = run.sightings_created_count === null || run.sightings_created_count === undefined
    ? null
    : Math.min(run.sightings_created_count, summary.sightings);
  const sightingParts = createdSightings === null
    ? [count('{count, plural, one {# sighting} other {# sightings}}', summary.sightings)]
    : [
        count('{count, plural, one {# sighting created} other {# sightings created}}', createdSightings),
        count('{count, plural, one {# sighting updated} other {# sightings updated}}', summary.sightings - createdSightings),
      ];
  const parts = [
    ...sightingParts,
    count('{count, plural, one {# observed data} other {# observed data}}', summary.observed_data),
    count('{count, plural, one {# observable} other {# observables}}', summary.observables),
    count('{count, plural, one {# other object} other {# other objects}}', summary.others),
    run.incident_id && run.incident_continued ? t_i18n('hits added to the open incident') : null,
    run.incident_id && !run.incident_continued ? count('{count, plural, one {# incident} other {# incidents}}', 1) : null,
  ].filter((part): part is string => !!part);
  const completed = run.hunt_run_status === 'completed';
  if (!completed && parts.length === 0) {
    return null;
  }
  const reasons: string[] = [];
  // The type of a hunt the user cannot read is unknown: no reason is given rather than a wrong one
  const huntType = run.hunt ? (run.hunt.hunt_type ?? 'telemetry') : null;
  if (completed && (run.hits_count ?? 0) > 0 && huntType) {
    if (huntType === 'telemetry' && summary.sightings === 0) {
      reasons.push(run.security_platform_id
        ? t_i18n('No sighting: the hunt names no technique or indicator to sight.')
        : t_i18n('No sighting: the run has no security platform.'));
    }
    if (huntExtractsObservables(huntType) && summary.observables === 0 && summary.observed_data === 0) {
      reasons.push(t_i18n('No observable: the hits carried no value of the types to extract, or the hunt connector does not support these types.'));
    }
  }
  return { produced: parts.length > 0 ? parts.join(', ') : t_i18n('Nothing'), reasons };
};

type ResultEdges = NonNullable<NonNullable<NonNullable<HuntRunResults_data$data['huntRun']>['results']>['edges']>;
type Result = NonNullable<NonNullable<ResultEdges[number]>['node']>;
type ResultRow = Result & { readonly id: string };

const readableResults = (edges?: ResultEdges | null): ResultRow[] => (edges ?? [])
  .map((edge) => edge?.node)
  .filter((node): node is ResultRow => !!node?.id);

/** What a run produced and how many objects it wrote that the user can read, for the summary of the run page. */
export const useHuntRunKnowledge = (data: HuntRunResults_data$key) => {
  const { t_i18n } = useFormatter();
  const { huntRun } = useFragment(huntRunResultsFragment, data);
  return {
    knowledge: huntRun ? huntRunKnowledge(huntRun, t_i18n) : null,
    total: huntRun?.results?.pageInfo.globalCount ?? readableResults(huntRun?.results?.edges).length,
  };
};

interface HuntRunResultsProps {
  data: HuntRunResults_data$key;
  runId: string;
  cardRef?: React.RefObject<HTMLDivElement | null>;
}

/** The objects a run wrote that the user can read, a page at a time, with their total. */
const HuntRunResults = ({ data, runId, cardRef }: HuntRunResultsProps) => {
  const theme = useTheme<Theme>();
  const { t_i18n, n } = useFormatter();
  const { data: { huntRun }, hasNext, loadNext, isLoadingNext } = usePaginationFragment<HuntRunResultsPaginationQuery, HuntRunResults_data$key>(
    huntRunResultsFragment,
    data,
  );
  const storageKey = `hunt-run-${runId}-results`;
  const sort = useHuntRunTableSort(storageKey, { orderAsc: true });
  const results = readableResults(huntRun?.results?.edges);
  if (results.length === 0) {
    return null;
  }
  const typeLabel = (result: ResultRow) => (result.entity_type ? t_i18n(`entity_${result.entity_type}`) : '');
  const sortValues: Record<string, (row: ResultRow) => HuntRunSortValue> = {
    entity_type: typeLabel,
    name: (result) => result.representative?.main ?? result.id,
    created_at: (result) => result.created_at,
    updated_at: (result) => result.updated_at,
  };
  // A sort of the pages loaded so far would put rows first that the next pages may not
  const sortable = !hasNext;
  const rows = sortable ? sortHuntRunRows(results, sort.sortBy ? sortValues[sort.sortBy] : undefined, sort.orderAsc) : results;
  const total = huntRun?.results?.pageInfo.globalCount ?? results.length;
  return (
    <div ref={cardRef} data-testid="hunt-run-results">
      <Card title={t_i18n('Results')}>
        <HuntRunTable
          storageKey={storageKey}
          initialValues={sort.initialValues}
          onSort={sort.onSort}
          rows={rows}
          label={t_i18n('Results')}
          testId="hunt-run-results-table"
          getComputeLink={(result: ResultRow) => huntRunResultLink(result) ?? undefined}
          dataColumns={{
            entity_type: {
              id: 'entity_type',
              label: 'Type',
              percentWidth: 20,
              isSortable: sortable,
              render: (result: ResultRow) => (
                <span style={{ display: 'flex', alignItems: 'center', gap: theme.spacing(1), minWidth: 0 }}>
                  <ItemIcon type={result.entity_type} size="small" />
                  <HuntRunCut value={typeLabel(result)} />
                </span>
              ),
            },
            name: { id: 'name', label: 'Name', percentWidth: 44, isSortable: sortable, render: (result: ResultRow) => huntRunTextCell(result.representative?.main ?? result.id) },
            created_at: { id: 'created_at', label: 'Created', percentWidth: 18, isSortable: sortable, render: (result: ResultRow) => <HuntRunDateCell date={result.created_at} /> },
            updated_at: { id: 'updated_at', label: 'Updated', percentWidth: 18, isSortable: sortable, render: (result: ResultRow) => <HuntRunDateCell date={result.updated_at} /> },
          }}
        />
        <div style={{ display: 'flex', alignItems: 'center', gap: theme.spacing(1.5), marginTop: theme.spacing(1) }}>
          <Text variant="content-caption" as="span">
            {t_i18n('{shown} of {total} results', { values: { shown: n(results.length), total: n(total) } })}
          </Text>
          {hasNext && (
            <Button
              variant="secondary"
              size="small"
              disabled={isLoadingNext}
              onClick={() => loadNext(HUNT_RUN_RESULTS_PAGE_SIZE)}
              data-testid="hunt-run-results-more"
            >
              {t_i18n('Show more')}
            </Button>
          )}
        </div>
      </Card>
    </div>
  );
};

export default HuntRunResults;
