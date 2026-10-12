import React, { lazy } from 'react';
import { Navigate, Route, Routes } from 'react-router';
import Security from '../../../../utils/Security';
import { KNOWLEDGE } from '../../../../utils/hooks/useGranted';
import { boundaryWrapper } from '../../Error';

const CurationProposals = lazy(() => import('./CurationProposals'));
const CurationProposal = lazy(() => import('./CurationProposal'));

/** The Inbox tab of the Curation hub: the open proposals and, under /<id>, one proposal compared side by side. */
const CurationInbox = () => (
  <Security needs={[KNOWLEDGE]} placeholder={<Navigate to="/dashboard" />}>
    <Routes>
      <Route index element={boundaryWrapper(CurationProposals)} />
      <Route path=":proposalId" element={boundaryWrapper(CurationProposal)} />
    </Routes>
  </Security>
);

export default CurationInbox;
