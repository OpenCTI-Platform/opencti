import React, { Suspense, useState } from 'react';
import { graphql, useLazyLoadQuery } from 'react-relay';
import Stack from '@mui/material/Stack';
import { SourceBranch } from 'mdi-material-ui';
import Button from '@common/button/Button';
import Drawer from '@components/common/drawer/Drawer';
import Label from '../../../../components/common/label/Label';
import { useFormatter } from '../../../../components/i18n';
import ProvenanceBadge from './ProvenanceBadge';
import ProvenanceSourcesPanel from './ProvenanceSourcesPanel';
import { ProvenanceSummaryQuery } from './__generated__/ProvenanceSummaryQuery.graphql';

const provenanceSummaryQuery = graphql`
  query ProvenanceSummaryQuery($id: String!) {
    stixObjectOrStixRelationship(id: $id) {
      ... on StixCoreObject {
        id
        corroboration_count
        freshness_days
        freshness_stale
        has_conflicts
      }
      ... on StixCoreRelationship {
        id
        corroboration_count
        freshness_days
        freshness_stale
        has_conflicts
      }
      ... on StixSightingRelationship {
        id
        corroboration_count
        freshness_days
        freshness_stale
        has_conflicts
      }
    }
  }
`;

interface ProvenanceSummaryProps {
  id: string;
  sx?: Record<string, unknown>;
}

const ProvenanceSummaryContent = ({ id, fetchKey, onOpen }: { id: string; fetchKey: number; onOpen: () => void }) => {
  const { t_i18n } = useFormatter();
  const data = useLazyLoadQuery<ProvenanceSummaryQuery>(provenanceSummaryQuery, { id }, { fetchPolicy: 'store-and-network', fetchKey });
  const element = data.stixObjectOrStixRelationship;
  return (
    <Stack direction="row" alignItems="center" gap={1} flexWrap="wrap">
      <ProvenanceBadge
        corroborationCount={element?.corroboration_count}
        freshnessDays={element?.freshness_days}
        stale={element?.freshness_stale}
        hasConflicts={element?.has_conflicts}
      />
      <Button variant="tertiary" size="small" startIcon={<SourceBranch fontSize="small" />} onClick={onOpen} data-testid="provenance-open-sources">
        {element?.has_conflicts ? t_i18n('Sources and conflicts') : t_i18n('View sources')}
      </Button>
    </Stack>
  );
};

/**
 * Corroboration, freshness and conflicts at a glance, with the full Sources panel in a drawer.
 */
const ProvenanceSummary = ({ id, sx }: ProvenanceSummaryProps) => {
  const { t_i18n } = useFormatter();
  const [open, setOpen] = useState(false);
  const [fetchKey, setFetchKey] = useState(0);
  return (
    <div data-testid="provenance-summary">
      <Label sx={sx}>{t_i18n('Provenance')}</Label>
      <Suspense fallback={<span>-</span>}>
        <ProvenanceSummaryContent id={id} fetchKey={fetchKey} onOpen={() => setOpen(true)} />
      </Suspense>
      <Drawer title={t_i18n('Sources')} open={open} onClose={() => setOpen(false)}>
        {open ? <ProvenanceSourcesPanel id={id} onChange={() => setFetchKey(fetchKey + 1)} /> : null}
      </Drawer>
    </div>
  );
};

export default ProvenanceSummary;
