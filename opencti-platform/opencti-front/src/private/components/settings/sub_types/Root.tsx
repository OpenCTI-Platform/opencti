import React, { Suspense } from 'react';
import { Route, Routes, useParams } from 'react-router-dom';
import EEGuard from '@components/common/entreprise_edition/EEGuard';
import Loader from '../../../../components/Loader';
import ErrorNotFound from '../../../../components/ErrorNotFound';
import SubType from './SubType';
import FintelTemplate from './fintel_templates/FintelTemplate';

const RootSubType = () => {
  const { subTypeId } = useParams<{ subTypeId?: string }>();
  if (!subTypeId) return <ErrorNotFound/>;

  return (
    <Suspense fallback={<Loader />}>
      <Routes>
        <Route path="/" element={<SubType />} />
        <Route
          path="/templates/:templateId"
          element={(
            <EEGuard redirect={`/dashboard/settings/customization/entity_types/${subTypeId}`}>
              <FintelTemplate />
            </EEGuard>
          )}
        />
      </Routes>
    </Suspense>
  );
};

export default RootSubType;
