import React, { useState } from 'react';
import Typography from '@mui/material/Typography';
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@filigran/design-system';
import { useFormatter } from '../../../../components/i18n';
import useConnectedDocumentModifier from '../../../../utils/hooks/useConnectedDocumentModifier';
import type { FilterGroup } from '../../../../utils/filters/filtersHelpers-types';
import ProvenanceKnowledgeRelationships from './ProvenanceKnowledgeRelationships';
import ProvenanceKnowledgeEntities from './ProvenanceKnowledgeEntities';
import ProvenanceKnowledgeSightings from './ProvenanceKnowledgeSightings';

const STALE_FILTERS: FilterGroup = {
  mode: 'and',
  filters: [{ key: 'freshness_stale', values: ['true'], operator: 'eq', mode: 'or' }],
  filterGroups: [],
};

/**
 * Stale knowledge tab of the Curation hub: knowledge flagged by the knowledge decay rules because no source
 * re-asserted it for too long.
 */
const StaleKnowledge = () => {
  const { t_i18n } = useFormatter();
  const { setTitle } = useConnectedDocumentModifier();
  setTitle(t_i18n('Stale knowledge | Curation | Data'));
  const [tab, setTab] = useState('relationships');
  return (
    <div data-testid="provenance-stale-page">
      <Typography variant="body2" sx={{ marginBottom: 2 }}>
        {t_i18n('Knowledge that no source re-asserted within the delay of its knowledge decay rule. Confirm it, update it or let the rule policy apply.')}
      </Typography>
      <Tabs value={tab} onValueChange={setTab}>
        <TabsList>
          <TabsTrigger value="relationships">{t_i18n('Relationships')}</TabsTrigger>
          <TabsTrigger value="entities">{t_i18n('Entities')}</TabsTrigger>
          <TabsTrigger value="sightings">{t_i18n('Sightings')}</TabsTrigger>
        </TabsList>
        <TabsContent value="relationships">
          {tab === 'relationships' && <ProvenanceKnowledgeRelationships storageKey="provenance-stale-relationships" fixedFilters={STALE_FILTERS} />}
        </TabsContent>
        <TabsContent value="entities">
          {tab === 'entities' && <ProvenanceKnowledgeEntities storageKey="provenance-stale-entities" fixedFilters={STALE_FILTERS} />}
        </TabsContent>
        <TabsContent value="sightings">
          {tab === 'sightings' && <ProvenanceKnowledgeSightings storageKey="provenance-stale-sightings" fixedFilters={STALE_FILTERS} />}
        </TabsContent>
      </Tabs>
    </div>
  );
};

export default StaleKnowledge;
