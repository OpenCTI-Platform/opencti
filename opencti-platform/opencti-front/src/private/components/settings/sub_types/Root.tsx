import React, { Suspense } from 'react';
import { Route, Routes, useParams } from 'react-router-dom';
import { graphql, useLazyLoadQuery } from 'react-relay';
import { RootSubTypeQuery } from '@components/settings/sub_types/__generated__/RootSubTypeQuery.graphql';
import Loader from '../../../../components/Loader';
import ErrorNotFound from '../../../../components/ErrorNotFound';
import SubType from './SubType';
import FintelTemplate from './fintel_templates/FintelTemplate';

export const subTypeQuery = graphql`
  query RootSubTypeQuery($id: String!) {
    subType(id: $id) {
      ...SubType_subType
    }
  }
`;

const RootSubType = () => {
  const { subTypeId } = useParams<{ subTypeId?: string }>();

  if (!subTypeId) return <ErrorNotFound/>;
  const { subType } = useLazyLoadQuery<RootSubTypeQuery>(subTypeQuery, { id: subTypeId });
  if (!subType) return <ErrorNotFound/>;

  return (
    <Suspense fallback={<Loader />}>
      <Routes>
        <Route path="/" element={<SubType data={subType}/>} />
        <Route path="/templates/:templateId" element={<FintelTemplate />} />
      </Routes>
    </Suspense>
  );
};

export default RootSubType;
