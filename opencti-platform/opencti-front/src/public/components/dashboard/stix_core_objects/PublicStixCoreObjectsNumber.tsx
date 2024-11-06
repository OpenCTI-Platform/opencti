import { graphql, PreloadedQuery, usePreloadedQuery } from 'react-relay';
import React from 'react';
import useQueryLoading from '../../../../utils/hooks/useQueryLoading';
import { PublicStixCoreObjectsNumberQuery } from './__generated__/PublicStixCoreObjectsNumberQuery.graphql';
import WidgetContainer from '../../../../components/dashboard/WidgetContainer';
import { useFormatter } from '../../../../components/i18n';
import WidgetNumber from '../../../../components/dashboard/WidgetNumber';
import WidgetNoData from '../../../../components/dashboard/WidgetNoData';
import type { PublicWidgetContainerProps } from '../PublicWidgetContainerProps';
import Loader, { LoaderVariant } from '../../../../components/Loader';

const publicStixCoreObjectsNumberQuery = graphql`
  query PublicStixCoreObjectsNumberQuery(
    $startDate: DateTime
    $endDate: DateTime
    $uriKey: String!
    $widgetId : String!
  ) {
    publicStixCoreObjectsNumber(
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

interface PublicStixCoreObjectsNumberComponentProps {
  queryRef: PreloadedQuery<PublicStixCoreObjectsNumberQuery>
}

const PublicStixCoreObjectsNumberComponent = ({
  queryRef,
}: PublicStixCoreObjectsNumberComponentProps) => {
  const { publicStixCoreObjectsNumber } = usePreloadedQuery(
    publicStixCoreObjectsNumberQuery,
    queryRef,
  );

  if (publicStixCoreObjectsNumber) {
    const { total, count } = publicStixCoreObjectsNumber;
    return <WidgetNumber total={total} value={count} />;
  }
  return <WidgetNoData />;
};

const PublicStixCoreObjectsNumber = ({
  uriKey,
  widget,
  startDate,
  endDate,
  title,
}: PublicWidgetContainerProps) => {
  const { t_i18n } = useFormatter();
  const { id, parameters } = widget;
  const queryRef = useQueryLoading<PublicStixCoreObjectsNumberQuery>(
    publicStixCoreObjectsNumberQuery,
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
          <PublicStixCoreObjectsNumberComponent queryRef={queryRef} />
        </React.Suspense>
      ) : (
        <Loader variant={LoaderVariant.inElement} />
      )}
    </WidgetContainer>
  );
};

export default PublicStixCoreObjectsNumber;
