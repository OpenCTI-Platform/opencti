import React, { Suspense, useState } from 'react';
import Box from '@mui/material/Box';
import Typography from '@mui/material/Typography';
import { useFormatter } from '../../../../components/i18n';
import useConnectedDocumentModifier from '../../../../utils/hooks/useConnectedDocumentModifier';
import ProvenanceKnowledgeRelationships from './ProvenanceKnowledgeRelationships';
import ProvenanceKnowledgeEntities from './ProvenanceKnowledgeEntities';
import ProvenanceKnowledgeSightings from './ProvenanceKnowledgeSightings';
import ProvenanceKpiStrip, { type ProvenanceKind } from './ProvenanceKpiStrip';
import useProvenanceTrackedFilters from './useProvenanceTrackedFilters';
import { CONFLICTS_FILTERS } from './provenanceCurationCounts';

/**
 * Conflicts tab of the Curation hub: knowledge on which sources disagree, with the losing values of the upsert
 * resolution ready to be adopted or dismissed.
 */
const SourceConflicts = () => {
  const { t_i18n } = useFormatter();
  const { setTitle } = useConnectedDocumentModifier();
  setTitle(t_i18n('Conflicts | Curation | Data'));
  const [kind, setKind] = useState<ProvenanceKind>('entities');
  const filters = useProvenanceTrackedFilters(CONFLICTS_FILTERS);
  const emptyMessage = t_i18n('No conflict - your sources agree on every field.');
  return (
    <div data-testid="provenance-conflicts-page">
      <Typography variant="body2" sx={{ marginBottom: 2 }}>
        {t_i18n('Fields on which sources proposed different values. Open the sources of an element to adopt or dismiss an alternative value.')}
      </Typography>
      <Suspense fallback={<Box sx={{ minHeight: 32 }} />}>
        <ProvenanceKpiStrip filters={filters} value={kind} onChange={setKind} label={t_i18n('Open conflicts by kind of knowledge')} />
      </Suspense>
      <Box sx={{ marginTop: 3 }}>
        {kind === 'entities' && (
          <ProvenanceKnowledgeEntities storageKey="provenance-conflicts-entities" fixedFilters={filters} withConflicts emptyMessage={emptyMessage} />
        )}
        {kind === 'relationships' && (
          <ProvenanceKnowledgeRelationships storageKey="provenance-conflicts-relationships" fixedFilters={filters} withConflicts emptyMessage={emptyMessage} />
        )}
        {kind === 'sightings' && (
          <ProvenanceKnowledgeSightings storageKey="provenance-conflicts-sightings" fixedFilters={filters} withConflicts emptyMessage={emptyMessage} />
        )}
      </Box>
    </div>
  );
};

export default SourceConflicts;
