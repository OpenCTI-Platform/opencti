import React, { Suspense } from 'react';
import { Route, Routes, useParams } from 'react-router-dom';
import { useLazyLoadQuery } from 'react-relay';
import EEGuard from '@components/common/entreprise_edition/EEGuard';
import { SubTypeQuery } from '@components/settings/sub_types/__generated__/SubTypeQuery.graphql';
import Loader from '../../../../components/Loader';
import ErrorNotFound from '../../../../components/ErrorNotFound';
import SubType, { subTypeQuery } from './SubType';
import FintelTemplate from './fintel_templates/FintelTemplate';
import useQueryLoading from '../../../../utils/hooks/useQueryLoading';

const RootSubType = () => {
  const { subTypeId } = useParams<{ subTypeId?: string }>();
  if (!subTypeId) return <ErrorNotFound/>;

  const subTypeRef = useQueryLoading<SubTypeQuery>(subTypeQuery, { id: subTypeId });

  return (
    <Suspense fallback={<Loader />}>
      {subTypeRef && (
        <Routes>
          <Route path="/" element={<SubType queryRef={subTypeRef} />} />
          <Route
            path="/templates/:templateId"
            element={(
              <EEGuard redirect={`/dashboard/settings/customization/entity_types/${subTypeId}`}>
                <FintelTemplate />
              </EEGuard>
            )}
          />
        </Routes>
      )}
    </Suspense>
  );
};

export default RootSubType;
