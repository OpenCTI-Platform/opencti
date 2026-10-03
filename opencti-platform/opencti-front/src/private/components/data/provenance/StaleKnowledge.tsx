import React, { useState } from 'react';
import Typography from '@mui/material/Typography';
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@filigran/design-system';
import Breadcrumbs from '../../../../components/Breadcrumbs';
import { useFormatter } from '../../../../components/i18n';
import useConnectedDocumentModifier from '../../../../utils/hooks/useConnectedDocumentModifier';
import type { FilterGroup } from '../../../../utils/filters/filtersHelpers-types';
import ProvenanceKnowledgeRelationships from './ProvenanceKnowledgeRelationships';
import ProvenanceKnowledgeEntities from './ProvenanceKnowledgeEntities';

const STALE_FILTERS: FilterGroup = {
  mode: 'and',
  filters: [{ key: 'freshness_stale', values: ['true'], operator: 'eq', mode: 'or' }],
  filterGroups: [],
};

/**
 * Knowledge flagged by the knowledge decay rules: no source re-asserted it for too long.
 */
const StaleKnowledge = () => {
  const { t_i18n } = useFormatter();
  const { setTitle } = useConnectedDocumentModifier();
  setTitle(t_i18n('Stale knowledge | Provenance | Data'));
  const [tab, setTab] = useState('relationships');
  return (
    <div data-testid="provenance-stale-page">
      <Breadcrumbs elements={[{ label: t_i18n('Data') }, { label: t_i18n('Provenance') }, { label: t_i18n('Stale knowledge'), current: true }]} />
      <Typography variant="body2" sx={{ marginBottom: 2 }}>
        {t_i18n('Knowledge that no source re-asserted within the delay of its knowledge decay rule. Confirm it, update it or let the rule policy apply.')}
      </Typography>
      <Tabs value={tab} onValueChange={setTab}>
        <TabsList>
          <TabsTrigger value="relationships">{t_i18n('Relationships')}</TabsTrigger>
          <TabsTrigger value="entities">{t_i18n('Entities')}</TabsTrigger>
        </TabsList>
        <TabsContent value="relationships">
          {tab === 'relationships' && <ProvenanceKnowledgeRelationships storageKey="provenance-stale-relationships" fixedFilters={STALE_FILTERS} />}
        </TabsContent>
        <TabsContent value="entities">
          {tab === 'entities' && <ProvenanceKnowledgeEntities storageKey="provenance-stale-entities" fixedFilters={STALE_FILTERS} />}
        </TabsContent>
      </Tabs>
    </div>
  );
};

export default StaleKnowledge;
