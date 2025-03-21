import React, { lazy } from 'react';
import { Navigate, Route, Routes } from 'react-router-dom';
import { boundaryWrapper } from '../Error';
import useDraftContext from '../../../utils/hooks/useDraftContext';
import useHelper from '../../../utils/hooks/useHelper';

const Drafts = lazy(() => import('./Drafts'));
const DraftRoot = lazy(() => import('./DraftRoot'));

const Root = () => {
  const draftContext = useDraftContext();

  const { isFeatureEnable } = useHelper();
  const isNewImportScreensEnabled = isFeatureEnable('NEW_IMPORT_SCREENS');

  return (
    <Routes>
      <Route
        path="/"
        element={draftContext?.id
          ? <Navigate
              to={isNewImportScreensEnabled ? `/dashboard/data/import/draft/${draftContext.id}/` : `/dashboard/drafts/${draftContext.id}/`}
              replace={true}
            />
          : boundaryWrapper(Drafts)
        }
      />
      <Route
        path="/:draftId/*"
        element={boundaryWrapper(DraftRoot)}
      />
    </Routes>
  );
};

export default Root;
