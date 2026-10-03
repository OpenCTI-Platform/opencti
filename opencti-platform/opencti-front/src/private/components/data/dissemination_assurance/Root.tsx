import React, { lazy } from 'react';
import { Navigate, Route, Routes } from 'react-router';
import { boundaryWrapper } from '../../Error';
import Security from '../../../../utils/Security';
import { KNOWLEDGE } from '../../../../utils/hooks/useGranted';
import { PATH_DISSEMINATION_ASSURANCE_OVERVIEW } from './disseminationAssuranceUtils';

const DisseminationAssuranceOverview = lazy(() => import('./DisseminationAssuranceOverview'));
const DisseminationAssuranceLists = lazy(() => import('./DisseminationAssuranceLists'));
const IocValidationRequests = lazy(() => import('./IocValidationRequests'));

/** The Dissemination assurance area of the Defense hub, mounted at `/dashboard/defense/assurance/*`. */
const Root = () => (
  <Security needs={[KNOWLEDGE]} placeholder={<Navigate to="/dashboard" />}>
    <Routes>
      <Route path="/overview" element={boundaryWrapper(DisseminationAssuranceOverview)} />
      <Route path="/lists" element={boundaryWrapper(DisseminationAssuranceLists)} />
      <Route path="/validations" element={boundaryWrapper(IocValidationRequests)} />
      <Route path="/*" element={<Navigate to={PATH_DISSEMINATION_ASSURANCE_OVERVIEW} replace={true} />} />
    </Routes>
  </Security>
);

export default Root;
