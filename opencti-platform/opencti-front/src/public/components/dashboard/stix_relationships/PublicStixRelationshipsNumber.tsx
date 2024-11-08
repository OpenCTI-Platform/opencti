import { graphql, PreloadedQuery, usePreloadedQuery } from 'react-relay';
import React from 'react';
import WidgetNumber from '../../../../components/dashboard/WidgetNumber';
import WidgetNoData from '../../../../components/dashboard/WidgetNoData';
import type { PublicWidgetContainerProps } from '../PublicWidgetContainerProps';
import { useFormatter } from '../../../../components/i18n';
import useQueryLoading from '../../../../utils/hooks/useQueryLoading';
import WidgetContainer from '../../../../components/dashboard/WidgetContainer';
import { PublicStixRelationshipsNumberQuery } from './__generated__/PublicStixRelationshipsNumberQuery.graphql';
import Loader, { LoaderVariant } from '../../../../components/Loader';

const publicStixRelationshipsNumberQuery = graphql`
  query PublicStixRelationshipsNumberQuery(
    $startDate: DateTime
    $endDate: DateTime
    $uriKey: String!
    $widgetId : String!
  ) {
    publicStixRelationshipsNumber(
      startDate: $startDate
      endDate: $endDate
      uriKey: $uriKey
      widgetId : $widgetId
    ) {
      total
      count
    }
  }
`;

interface PublicStixCoreRelationshipsNumberComponentProps {
  queryRef: PreloadedQuery<PublicStixRelationshipsNumberQuery>
}

const PublicStixCoreRelationshipsNumberComponent = ({
  queryRef,
}: PublicStixCoreRelationshipsNumberComponentProps) => {
  const { publicStixRelationshipsNumber } = usePreloadedQuery(
    publicStixRelationshipsNumberQuery,
    queryRef,
  );

  if (publicStixRelationshipsNumber) {
    const { total, count } = publicStixRelationshipsNumber;
    return <WidgetNumber total={total} value={count} />;
  }
  return <WidgetNoData />;
};

const PublicStixCoreRelationshipsNumber = ({
  uriKey,
  widget,
  startDate,
  endDate,
  title,
}: PublicWidgetContainerProps) => {
  const { t_i18n } = useFormatter();
  const { id, parameters } = widget;
  const queryRef = useQueryLoading<PublicStixRelationshipsNumberQuery>(
    publicStixRelationshipsNumberQuery,
    {
      uriKey,
      widgetId: id,
      startDate,
      endDate,
    },
  );

  return (
    <WidgetContainer
      title={parameters?.title ?? title ?? t_i18n('Entities number')}
      variant="inLine"
    >
      {queryRef ? (
        <React.Suspense fallback={<Loader variant={LoaderVariant.inElement} />}>
          <PublicStixCoreRelationshipsNumberComponent queryRef={queryRef} />
        </React.Suspense>
      ) : (
        <Loader variant={LoaderVariant.inElement} />
      )}
    </WidgetContainer>
  );
};

export default PublicStixCoreRelationshipsNumber;
