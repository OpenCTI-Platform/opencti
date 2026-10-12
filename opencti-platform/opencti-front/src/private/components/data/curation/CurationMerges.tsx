import React, { lazy } from 'react';
import { Navigate, Route, Routes, useParams } from 'react-router';
import Security from '../../../../utils/Security';
import { KNOWLEDGE } from '../../../../utils/hooks/useGranted';
import { boundaryWrapper } from '../../Error';
import { CURATION_MERGES_PATH } from './curationUtils';

const MergeRecords = lazy(() => import('./MergeRecords'));

// Generic entity links (notifications, history) point to <list>/<id>: a merge record opens in the list drawer.
const MergeRecordRedirect = () => {
  const { mergeRecordId } = useParams();
  return <Navigate to={`${CURATION_MERGES_PATH}?record=${mergeRecordId}`} replace={true} />;
};

/** The Merges tab of the Curation hub: every recorded merge of the platform, each one reversible from its drawer. */
const CurationMerges = () => (
  <Security needs={[KNOWLEDGE]} placeholder={<Navigate to="/dashboard" />}>
    <Routes>
      <Route index element={boundaryWrapper(MergeRecords)} />
      <Route path=":mergeRecordId" element={<MergeRecordRedirect />} />
    </Routes>
  </Security>
);

export default CurationMerges;
