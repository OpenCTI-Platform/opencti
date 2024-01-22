import { graphql, PreloadedQuery, usePreloadedQuery } from 'react-relay';
import React from 'react';
import useQueryLoading from '../../../utils/hooks/useQueryLoading';
import { PublicStixCoreObjectsNumberQuery } from './__generated__/PublicStixCoreObjectsNumberQuery.graphql';
import WidgetContainer from '../../../components/dashboard/WidgetContainer';
import { useFormatter } from '../../../components/i18n';
import WidgetLoader from '../../../components/dashboard/WidgetLoader';
import WidgetNumber from '../../../components/dashboard/WidgetNumber';
import WidgetNoData from '../../../components/dashboard/WidgetNoData';
import type { PublicManifestWidget } from './PublicManifest';

const publicStixCoreObjectsNumberQuery = graphql`
  query PublicStixCoreObjectsNumberQuery(
    $types: [String]
    $startDate: DateTime
    $endDate: DateTime
    $uriKey: String!
    $widgetId : String!
  ) {
    publicStixCoreObjectsNumber(
      types: $types
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

interface PublicStixCoreObjectsNumberProps {
  startDate: string | null | undefined
  endDate: string | null | undefined
  uriKey: string
  widget: PublicManifestWidget
}

const PublicStixCoreObjectsNumber = ({
  uriKey,
  widget,
  startDate,
  endDate,
}: PublicStixCoreObjectsNumberProps) => {
  const { t_i18n } = useFormatter();
  const { id, parameters } = widget;
  const queryRef = useQueryLoading<PublicStixCoreObjectsNumberQuery>(
    publicStixCoreObjectsNumberQuery,
    {
      uriKey,
      widgetId: id,
      types: ['Stix-Core-Object'],
      startDate,
      endDate,
    },
  );

  return (
    <WidgetContainer
      title={parameters.title ?? t_i18n('Entities number')}
      variant="inLine"
    >
      {queryRef ? (
        <React.Suspense fallback={<WidgetLoader />}>
          <PublicStixCoreObjectsNumberComponent queryRef={queryRef} />
        </React.Suspense>
      ) : (
        <WidgetLoader />
      )}
    </WidgetContainer>
  );
};

export default PublicStixCoreObjectsNumber;
