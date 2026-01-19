import { graphql, PreloadedQuery, usePreloadedQuery } from 'react-relay';
import React from 'react';
import WidgetNoData from '../../../../components/dashboard/WidgetNoData';
import type { PublicWidgetContainerProps } from '../PublicWidgetContainerProps';
import { useFormatter } from '../../../../components/i18n';
import useQueryLoading from '../../../../utils/hooks/useQueryLoading';
import WidgetContainer from '../../../../components/dashboard/WidgetContainer';
import { PublicStixRelationshipsNumberQuery } from './__generated__/PublicStixRelationshipsNumberQuery.graphql';
import Loader, { LoaderVariant } from '../../../../components/Loader';
import CardNumber from '../../../../components/common/card/CardNumber';

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
  title: string;
  queryRef: PreloadedQuery<PublicStixRelationshipsNumberQuery>;
}

const PublicStixCoreRelationshipsNumberComponent = ({
  title,
  queryRef,
}: PublicStixCoreRelationshipsNumberComponentProps) => {
  const { t_i18n } = useFormatter();
  const { publicStixRelationshipsNumber } = usePreloadedQuery(
    publicStixRelationshipsNumberQuery,
    queryRef,
  );

  if (publicStixRelationshipsNumber) {
    const { total, count } = publicStixRelationshipsNumber;
    return (
      <CardNumber
        label={title}
        value={total}
        diffLabel={t_i18n('24 hours')}
        diffValue={total - count}
      />
    );
  }
  return (
    <WidgetContainer>
      <WidgetNoData />
    </WidgetContainer>
  );
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
    <>
      {queryRef ? (
        <React.Suspense fallback={<Loader variant={LoaderVariant.inElement} />}>
          <PublicStixCoreRelationshipsNumberComponent
            title={parameters?.title ?? title ?? t_i18n('Entities number')}
            queryRef={queryRef}
          />
        </React.Suspense>
      ) : (
        <WidgetContainer>
          <Loader variant={LoaderVariant.inElement} />
        </WidgetContainer>
      )}
    </>
  );
};

export default PublicStixCoreRelationshipsNumber;
