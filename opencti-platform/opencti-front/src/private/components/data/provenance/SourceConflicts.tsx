import React, { useState } from 'react';
import Typography from '@mui/material/Typography';
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@filigran/design-system';
import { useFormatter } from '../../../../components/i18n';
import useConnectedDocumentModifier from '../../../../utils/hooks/useConnectedDocumentModifier';
import type { FilterGroup } from '../../../../utils/filters/filtersHelpers-types';
import ProvenanceKnowledgeRelationships from './ProvenanceKnowledgeRelationships';
import ProvenanceKnowledgeEntities from './ProvenanceKnowledgeEntities';
import ProvenanceKnowledgeSightings from './ProvenanceKnowledgeSightings';

const CONFLICTS_FILTERS: FilterGroup = {
  mode: 'and',
  filters: [{ key: 'has_conflicts', values: ['true'], operator: 'eq', mode: 'or' }],
  filterGroups: [],
};

/**
 * Conflicts tab of the Curation hub: knowledge on which sources disagree, with the losing values of the upsert
 * resolution ready to be adopted or dismissed.
 */
const SourceConflicts = () => {
  const { t_i18n } = useFormatter();
  const { setTitle } = useConnectedDocumentModifier();
  setTitle(t_i18n('Conflicts | Curation | Data'));
  const [tab, setTab] = useState('entities');
  return (
    <div data-testid="provenance-conflicts-page">
      <Typography variant="body2" sx={{ marginBottom: 2 }}>
        {t_i18n('Fields on which sources proposed different values. Open the sources of an element to adopt or dismiss an alternative value.')}
      </Typography>
      <Tabs value={tab} onValueChange={setTab}>
        <TabsList>
          <TabsTrigger value="entities">{t_i18n('Entities')}</TabsTrigger>
          <TabsTrigger value="relationships">{t_i18n('Relationships')}</TabsTrigger>
          <TabsTrigger value="sightings">{t_i18n('Sightings')}</TabsTrigger>
        </TabsList>
        <TabsContent value="entities">
          {tab === 'entities' && <ProvenanceKnowledgeEntities storageKey="provenance-conflicts-entities" fixedFilters={CONFLICTS_FILTERS} withConflicts />}
        </TabsContent>
        <TabsContent value="relationships">
          {tab === 'relationships' && <ProvenanceKnowledgeRelationships storageKey="provenance-conflicts-relationships" fixedFilters={CONFLICTS_FILTERS} withConflicts />}
        </TabsContent>
        <TabsContent value="sightings">
          {tab === 'sightings' && <ProvenanceKnowledgeSightings storageKey="provenance-conflicts-sightings" fixedFilters={CONFLICTS_FILTERS} withConflicts />}
        </TabsContent>
      </Tabs>
    </div>
  );
};

export default SourceConflicts;
