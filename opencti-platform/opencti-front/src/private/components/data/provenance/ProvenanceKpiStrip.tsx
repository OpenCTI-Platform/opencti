import React, { ReactNode } from 'react';
import { graphql, useLazyLoadQuery } from 'react-relay';
import { Button } from '@filigran/design-system';
import Stack from '@mui/material/Stack';
import { useFormatter } from '../../../../components/i18n';
import type { FilterGroup } from '../../../../utils/filters/filtersHelpers-types';
import useProvenanceCountsFetchKey from '../../common/provenance/provenanceCountsRefresh';
import { ProvenanceKpiStripQuery, ProvenanceKpiStripQuery$variables } from './__generated__/ProvenanceKpiStripQuery.graphql';

export const provenanceKpiStripQuery = graphql`
  query ProvenanceKpiStripQuery($filters: FilterGroup) {
    entities: stixCoreObjectsNumber(filters: $filters) { total }
    relationships: stixCoreRelationshipsNumber(filters: $filters) { total }
    sightings: stixSightingRelationshipsNumber(filters: $filters) { total }
  }
`;

export type ProvenanceKind = 'entities' | 'relationships' | 'sightings';

export const PROVENANCE_KINDS: ProvenanceKind[] = ['entities', 'relationships', 'sightings'];

// One translated string per kind, with its plural
const KIND_COUNT_LABELS: Record<ProvenanceKind, string> = {
  entities: '{count, plural, one {# entity} other {# entities}}',
  relationships: '{count, plural, one {# relationship} other {# relationships}}',
  sightings: '{count, plural, one {# sighting} other {# sightings}}',
};

interface ProvenanceKpiStripProps {
  // Same filters as the lists below, so that each counter announces the rows of its list
  filters: FilterGroup;
  value: ProvenanceKind;
  onChange: (kind: ProvenanceKind) => void;
  // Accessible name of the group of counters
  label: string;
  children?: ReactNode;
}

/**
 * Counters of a Curation tab by kind of knowledge: each one is a toggle that shows the list of its kind below.
 */
const ProvenanceKpiStrip = ({ filters, value, onChange, label, children }: ProvenanceKpiStripProps) => {
  const { t_i18n } = useFormatter();
  const fetchKey = useProvenanceCountsFetchKey();
  const data = useLazyLoadQuery<ProvenanceKpiStripQuery>(
    provenanceKpiStripQuery,
    { filters } as unknown as ProvenanceKpiStripQuery$variables,
    { fetchPolicy: 'store-and-network', fetchKey },
  );
  const counts: Record<ProvenanceKind, number> = {
    entities: data.entities?.total ?? 0,
    relationships: data.relationships?.total ?? 0,
    sightings: data.sightings?.total ?? 0,
  };
  return (
    <Stack direction="row" gap={1.5} alignItems="center" flexWrap="wrap" role="group" aria-label={label} data-testid="provenance-kpi-strip">
      {PROVENANCE_KINDS.map((kind) => (
        <Button
          key={kind}
          priority={value === kind ? 'primary' : 'secondary'}
          size="sm"
          aria-pressed={value === kind}
          onClick={() => onChange(kind)}
          data-testid={`provenance-kpi-${kind}`}
        >
          {t_i18n(KIND_COUNT_LABELS[kind], { values: { count: counts[kind] } })}
        </Button>
      ))}
      {children}
    </Stack>
  );
};

export default ProvenanceKpiStrip;
