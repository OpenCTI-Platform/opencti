import React, { Suspense } from 'react';
import { useParams } from 'react-router-dom';
import { graphql, useLazyLoadQuery } from 'react-relay';
import { RootSubTypeQuery } from '@components/settings/sub_types/__generated__/RootSubTypeQuery.graphql';
import Loader from '../../../../components/Loader';
import ErrorNotFound from '../../../../components/ErrorNotFound';
import SubType from './SubType';
import Breadcrumbs from '../../../../components/Breadcrumbs';
import { useFormatter } from '../../../../components/i18n';

export const subTypeQuery = graphql`
  query RootSubTypeQuery($id: String!) {
    subType(id: $id) {
      ...SubType_subType
    }
  }
`;

const RootSubType = () => {
  const { subTypeId } = useParams() as { subTypeId: string };
  const { t_i18n } = useFormatter();
  const data = useLazyLoadQuery<RootSubTypeQuery>(subTypeQuery, { id: subTypeId });

  return (
    <Suspense fallback={<Loader />}>
      {
        data.subType ? (
          <>
            <Breadcrumbs elements={[
              { label: t_i18n('Settings') },
              { label: t_i18n('Customization') },
              { label: t_i18n('Entity types'), link: '/dashboard/settings/customization/entity_types' },
            ]}
            />
            <SubType data={data.subType}/>
          </>
        ) : (
          <ErrorNotFound/>
        )}
    </Suspense>
  );
};

export default RootSubType;
