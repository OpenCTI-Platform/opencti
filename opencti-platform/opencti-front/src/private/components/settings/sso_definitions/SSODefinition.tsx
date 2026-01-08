import React, { Suspense } from 'react';
import { graphql, PreloadedQuery, usePreloadedQuery } from 'react-relay';
import { useParams } from 'react-router-dom';
import Loader from '../../../../components/Loader';
import ErrorNotFound from '../../../../components/ErrorNotFound';
import useQueryLoading from '../../../../utils/hooks/useQueryLoading';
import { SSODefinitionQuery } from './__generated__/SSODefinitionQuery.graphql';
import SSODefinitionOverview from '@components/settings/sso_definitions/SSODefinitionOverview';

export const ssoDefinitionQuery = graphql`
  query SSODefinitionQuery($id: String!) {
    singleSignOn(id: $id) {
      id
      name
      identifier
      label
      description
      enabled
      strategy
      organizations_management {
        organizations_path
        organizations_mapping
      }
      groups_management {
        group_attributes
        groups_path
        groups_mapping
        read_userinfo
      }
      configuration {
        key
        value
        type
      }
    }
  }
`;

interface SSODefinitionComponentProps {
  queryRef: PreloadedQuery<SSODefinitionQuery>;
}

const SSODefinitionComponent = ({ queryRef }: SSODefinitionComponentProps) => {
  const data = usePreloadedQuery<SSODefinitionQuery>(ssoDefinitionQuery, queryRef);
  const sso = data.singleSignOn;

  if (!sso) return <ErrorNotFound />;

  return <SSODefinitionOverview sso={sso} />;
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
