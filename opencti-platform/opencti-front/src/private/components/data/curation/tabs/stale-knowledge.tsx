import { lazy } from 'react';
import type { CurationTab } from '../curationTabs';
import { useStaleKnowledgeCount } from '../../provenance/provenanceCurationCounts';

const staleKnowledge: CurationTab = {
  order: 30,
  path: 'stale-knowledge',
  label: 'Stale knowledge',
  isAvailable: (modules) => modules.isProvenanceEnabled(),
  useBadgeCount: useStaleKnowledgeCount,
  component: lazy(() => import('../../provenance/StaleKnowledge')),
};

export default staleKnowledge;
