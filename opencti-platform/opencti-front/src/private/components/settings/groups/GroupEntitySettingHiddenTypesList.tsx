import React, { FunctionComponent } from 'react';
import { graphql, PreloadedQuery, usePreloadedQuery } from 'react-relay';
import EntitySettingHiddenTypesList from '../sub_types/entity_setting/EntitySettingHiddenTypesList';
import useQueryLoading from '../../../../utils/hooks/useQueryLoading';
import Loader, { LoaderVariant } from '../../../../components/Loader';
import { useFormatter } from '../../../../components/i18n';
import { GroupEntitySettingHiddenTypesListQuery } from './__generated__/GroupEntitySettingHiddenTypesListQuery.graphql';

const groupEntitySettingHiddenTypesListQuery = graphql`
  query GroupEntitySettingHiddenTypesListQuery {
    groups {
      edges {
        node {
          id
          name
          default_hidden_types
        }
      }
    }
  }
`;

const GroupHiddenTypesListComponent: FunctionComponent<{
  targetType: string
  queryRef: PreloadedQuery<GroupEntitySettingHiddenTypesListQuery>
}> = ({
  targetType,
  queryRef,
}) => {
  const { t } = useFormatter();
  const data = usePreloadedQuery<GroupEntitySettingHiddenTypesListQuery>(groupEntitySettingHiddenTypesListQuery, queryRef);
  const groups = data.groups?.edges?.map((e) => e?.node) ?? [];

  return (
    <EntitySettingHiddenTypesList
      targetType={targetType}
      nodes={groups}
      label={t('Hidden in groups')}
      link={'/dashboard/settings/accesses/groups/'}
      entityType={'Group'}
    />
  );
};
const GroupEntitySettingHiddenTypesList: FunctionComponent<{ targetType: string }> = ({ targetType }) => {
  const queryRef = useQueryLoading<GroupEntitySettingHiddenTypesListQuery>(groupEntitySettingHiddenTypesListQuery, {});
  return <>
    {queryRef && (
      <React.Suspense fallback={<Loader variant={LoaderVariant.inElement} />}>
        <GroupHiddenTypesListComponent queryRef={queryRef} targetType={targetType} />
      </React.Suspense>
    )}
  </>;
};

export default GroupEntitySettingHiddenTypesList;
