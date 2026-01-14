import React, { Suspense } from 'react';
import { graphql, PreloadedQuery, usePreloadedQuery } from 'react-relay';
import { useParams } from 'react-router-dom';
import Loader from '../../../../components/Loader';
import ErrorNotFound from '../../../../components/ErrorNotFound';
import useQueryLoading from '../../../../utils/hooks/useQueryLoading';
import { SSODefinitionQuery } from './__generated__/SSODefinitionQuery.graphql';
import SSODefinitionOverview from './SSODefinitionOverview';
import SSODefinitionHeader from './SSODefinitionHeader';

export const ssoDefinitionQuery = graphql`
  query SSODefinitionQuery($id: String!) {
    singleSignOn(id: $id) {
      ...SSODefinitionHeaderFragment
      ...SSODefinitionEditionFragment
    }
  }
`;

interface SSODefinitionComponentProps {
  queryRef: PreloadedQuery<SSODefinitionQuery>;
}

const SSODefinitionComponent = ({ queryRef }: SSODefinitionComponentProps) => {
  const { singleSignOn } = usePreloadedQuery<SSODefinitionQuery>(ssoDefinitionQuery, queryRef);
  if (!singleSignOn) return <ErrorNotFound />;

  return (
    <>
      <SSODefinitionHeader data={singleSignOn} editionData={singleSignOn} />
      <SSODefinitionOverview sso={singleSignOn} />
    </>

  );
};

const SSODefinition = () => {
  const { singleSignOnId } = useParams<{ singleSignOnId?: string }>();
  if (!singleSignOnId) return <ErrorNotFound />;

  const queryRef = useQueryLoading<SSODefinitionQuery>(ssoDefinitionQuery, {
    id: singleSignOnId,
  });

  return (
    <Suspense fallback={<Loader />}>
      {queryRef && <SSODefinitionComponent queryRef={queryRef} />}
    </Suspense>
  );
};

export default SSODefinition;
