import React, { FunctionComponent } from 'react';
import { graphql, PreloadedQuery, usePreloadedQuery } from 'react-relay';
import useQueryLoading from '../../../../utils/hooks/useQueryLoading';
import Loader, { LoaderVariant } from '../../../../components/Loader';
import { HiddenTypesInGroupsQuery } from '../hidden_types/__generated__/HiddenTypesInGroupsQuery.graphql';
import HiddenTypesIndicator from '../hidden_types/HiddenTypesIndicator';
import { useFormatter } from '../../../../components/i18n';

export const groupHiddenTypesIndicatorQuery = graphql`
  query GroupHiddenTypesIndicatorQuery {
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

interface GroupHiddenTypesIndicatorComponentProps {
  targetTypes: string[]
  platformHiddenTargetType: string
  queryRef: PreloadedQuery<HiddenTypesInGroupsQuery>
}

const GroupHiddenTypesIndicatorComponent: FunctionComponent<GroupHiddenTypesIndicatorComponentProps> = ({
  targetTypes,
  platformHiddenTargetType,
  queryRef,
}) => {
  const { t } = useFormatter();

  const data = usePreloadedQuery<HiddenTypesInGroupsQuery>(groupHiddenTypesIndicatorQuery, queryRef);
  const nodes = data.groups?.edges?.map((e) => e?.node) ?? [];
  return (
    <HiddenTypesIndicator
      targetTypes={targetTypes}
      platformHiddenTargetType={platformHiddenTargetType}
      nodes={nodes}
      label={t('Hidden in groups')}
    />
  );
};

interface GroupHiddenTypesIndicatorProps {
  targetTypes: string[],
  platformHiddenTargetType: string,
}

const GroupHiddenTypesIndicator: FunctionComponent<GroupHiddenTypesIndicatorProps> = ({
  targetTypes,
  platformHiddenTargetType,
}) => {
  const queryRef = useQueryLoading<HiddenTypesInGroupsQuery>(groupHiddenTypesIndicatorQuery, {});

  return (
    <>
      {queryRef && (
        <React.Suspense
          fallback={<Loader variant={LoaderVariant.inElement} />}
        >
          <GroupHiddenTypesIndicatorComponent queryRef={queryRef} targetTypes={targetTypes} platformHiddenTargetType={platformHiddenTargetType} />
        </React.Suspense>)
      }
    </>
  );
};

export default GroupHiddenTypesIndicator;
