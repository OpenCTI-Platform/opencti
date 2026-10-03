import React from 'react';
import { Navigate, Route, Routes } from 'react-router';
import NavToolbarMenu, { MenuEntry } from '@components/common/menus/NavToolbarMenu';
import PageContainer from '../../../../components/PageContainer';
import ProvenanceOverview from './ProvenanceOverview';
import StaleKnowledge from './StaleKnowledge';
import SourceConflicts from './SourceConflicts';

const PROVENANCE_MENU: MenuEntry[] = [
  { path: '/dashboard/data/provenance/overview', label: 'Overview' },
  { path: '/dashboard/data/provenance/stale', label: 'Stale knowledge' },
  { path: '/dashboard/data/provenance/conflicts', label: 'Conflicts' },
];

const ProvenanceRoot = () => {
  return (
    <div data-testid="data-provenance-page" style={{ height: '100%' }}>
      <NavToolbarMenu entries={PROVENANCE_MENU} />
      <PageContainer withRightMenu withGap style={{ height: '100%' }}>
        <Routes>
          <Route path="/overview" element={<ProvenanceOverview />} />
          <Route path="/stale" element={<StaleKnowledge />} />
          <Route path="/conflicts" element={<SourceConflicts />} />
          <Route index element={<Navigate to="/dashboard/data/provenance/overview" replace={true} />} />
        </Routes>
      </PageContainer>
    </div>
  );
};

export default ProvenanceRoot;
