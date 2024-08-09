import React, { Suspense } from 'react';
import { useParams } from 'react-router-dom';
import { graphql, useLazyLoadQuery } from 'react-relay';
import { RootSubTypeQuery } from '@components/settings/sub_types/__generated__/RootSubTypeQuery.graphql';
import Loader from '../../../../components/Loader';
import ErrorNotFound from '../../../../components/ErrorNotFound';
import SubType from './SubType';

export const subTypeQuery = graphql`
  query RootSubTypeQuery($id: String!) {
    subType(id: $id) {
      ...SubType_subType
    }
  }
`;

const RootSubType = () => {
  const { subTypeId } = useParams() as { subTypeId: string };

  const data = useLazyLoadQuery<RootSubTypeQuery>(subTypeQuery, { id: subTypeId });

  return (
    <Suspense fallback={<Loader />}>
      {
        data.subType ? <SubType data={data.subType} /> : <ErrorNotFound />
      }
    </Suspense>
  );
};

export default RootSubType;
