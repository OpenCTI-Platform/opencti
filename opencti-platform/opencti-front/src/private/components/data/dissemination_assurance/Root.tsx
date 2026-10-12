import React, { type ComponentType, lazy, type LazyExoticComponent } from 'react';
import { Navigate, Route, Routes, useParams } from 'react-router';
import { boundaryWrapper } from '../../Error';
import Security from '../../../../utils/Security';
import { KNOWLEDGE } from '../../../../utils/hooks/useGranted';
import { DISSEMINATION_ASSURANCE_SECTIONS, type DisseminationAssuranceSectionPath, PATH_DISSEMINATION_ASSURANCE } from './disseminationAssuranceUtils';

const SECTION_COMPONENTS: Record<DisseminationAssuranceSectionPath, LazyExoticComponent<ComponentType>> = {
  overview: lazy(() => import('./DisseminationAssuranceOverview')),
  lists: lazy(() => import('./DisseminationAssuranceLists')),
  validations: lazy(() => import('./IocValidationRequests')),
};

const DEFAULT_SECTION = `${PATH_DISSEMINATION_ASSURANCE}/${DISSEMINATION_ASSURANCE_SECTIONS[0].path}`;

const DisseminationAssuranceSection = () => {
  const { tab } = useParams();
  const section = DISSEMINATION_ASSURANCE_SECTIONS.find((entry) => entry.path === tab);
  if (!section) {
    return <Navigate to={DEFAULT_SECTION} replace={true} />;
  }
  return boundaryWrapper(SECTION_COMPONENTS[section.path]);
};

/**
 * The Dissemination assurance area of the Defense hub, mounted at `/dashboard/defense/assurance/*`.
 * The hub renders the page, the breadcrumb and the section tabs; the area renders the open section only.
 */
const Root = () => (
  <Security needs={[KNOWLEDGE]} placeholder={<Navigate to="/dashboard" />}>
    <Routes>
      <Route path="/" element={<Navigate to={DEFAULT_SECTION} replace={true} />} />
      <Route path="/:tab/*" element={<DisseminationAssuranceSection />} />
    </Routes>
  </Security>
);

export default Root;
