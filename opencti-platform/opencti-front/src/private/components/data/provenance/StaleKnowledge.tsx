import React, { Suspense, useState } from 'react';
import { graphql, useLazyLoadQuery } from 'react-relay';
import Box from '@mui/material/Box';
import Typography from '@mui/material/Typography';
import { useFormatter } from '../../../../components/i18n';
import useConnectedDocumentModifier from '../../../../utils/hooks/useConnectedDocumentModifier';
import ProvenanceKnowledgeRelationships from './ProvenanceKnowledgeRelationships';
import ProvenanceKnowledgeEntities from './ProvenanceKnowledgeEntities';
import ProvenanceKnowledgeSightings from './ProvenanceKnowledgeSightings';
import ProvenanceKpiStrip, { type ProvenanceKind } from './ProvenanceKpiStrip';
import useProvenanceTrackedFilters from './useProvenanceTrackedFilters';
import { STALE_FILTERS } from './provenanceCurationCounts';
import useGranted, { SETTINGS_SETCUSTOMIZATION } from '../../../../utils/hooks/useGranted';
import { StaleKnowledgeRulesQuery } from './__generated__/StaleKnowledgeRulesQuery.graphql';
import KnowledgeDecayRulesLink from '../../settings/decay/KnowledgeDecayRulesLink';

const staleKnowledgeRulesQuery = graphql`
  query StaleKnowledgeRulesQuery {
    knowledgeDecayRulesInvolvedCount
  }
`;

// Number of knowledge decay rules that currently flag knowledge, next to the counters by kind
const StaleKnowledgeRules = () => {
  const { t_i18n } = useFormatter();
  const canOpenDecayRules = useGranted([SETTINGS_SETCUSTOMIZATION]);
  const { knowledgeDecayRulesInvolvedCount: involved } = useLazyLoadQuery<StaleKnowledgeRulesQuery>(staleKnowledgeRulesQuery, {}, { fetchPolicy: 'store-and-network' });
  return (
    <Typography variant="body2" color="textSecondary" data-testid="provenance-stale-rules">
      {t_i18n('{count, plural, =0 {No knowledge decay rule flags knowledge} one {# knowledge decay rule involved} other {# knowledge decay rules involved}}', { values: { count: involved } })}
      {canOpenDecayRules && (
        <>
          {' - '}
          <KnowledgeDecayRulesLink>{t_i18n('Open the decay rules')}</KnowledgeDecayRulesLink>
        </>
      )}
    </Typography>
  );
};

/**
 * Stale knowledge tab of the Curation hub: knowledge flagged by the knowledge decay rules because no source
 * re-asserted it for too long.
 */
const StaleKnowledge = () => {
  const { t_i18n } = useFormatter();
  const { setTitle } = useConnectedDocumentModifier();
  setTitle(t_i18n('Stale knowledge | Curation | Data'));
  const [kind, setKind] = useState<ProvenanceKind>('entities');
  const filters = useProvenanceTrackedFilters(STALE_FILTERS);
  const emptyMessage = t_i18n('No stale knowledge - every element was re-asserted within its decay rule.');
  return (
    <div data-testid="provenance-stale-page">
      <Typography variant="body2" sx={{ marginBottom: 2 }}>
        {t_i18n('Knowledge that no source re-asserted within the delay of its knowledge decay rule. Confirm it, update it or let the rule policy apply.')}
      </Typography>
      <Suspense fallback={<Box sx={{ minHeight: 32 }} />}>
        <ProvenanceKpiStrip filters={filters} value={kind} onChange={setKind} label={t_i18n('Stale knowledge by kind of knowledge')}>
          <StaleKnowledgeRules />
        </ProvenanceKpiStrip>
      </Suspense>
      <Box sx={{ marginTop: 3 }}>
        {kind === 'entities' && <ProvenanceKnowledgeEntities storageKey="provenance-stale-entities" fixedFilters={filters} emptyMessage={emptyMessage} />}
        {kind === 'relationships' && (
          <ProvenanceKnowledgeRelationships storageKey="provenance-stale-relationships" fixedFilters={filters} emptyMessage={emptyMessage} />
        )}
        {kind === 'sightings' && <ProvenanceKnowledgeSightings storageKey="provenance-stale-sightings" fixedFilters={filters} emptyMessage={emptyMessage} />}
      </Box>
    </div>
  );
};

export default StaleKnowledge;
