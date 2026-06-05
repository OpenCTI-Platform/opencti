import React, { useRef } from 'react';
import { graphql, PreloadedQuery, usePreloadedQuery } from 'react-relay';
import { WidgetColumn, WidgetHost, type WidgetParameters } from '../../../utils/widget/widget';
import { useFormatter } from '../../../components/i18n';
import useDashboardViz from '../../../components/dashboard/useDashboardViz';
import { WidgetColumnsLayout } from '@components/widgets/WidgetCustomAttributesColumnsInput';
import WidgetContainer from '../../../components/dashboard/WidgetContainer';
import WidgetNoHostEntity from '../../../components/dashboard/WidgetNoHostEntity';
import WidgetCustomAttributes from '@components/widgets/WidgetCustomAttribute';
import WidgetNoData from '../../../components/dashboard/WidgetNoData';
import Loader, { LoaderVariant } from '../../../components/Loader';
import { StixCoreObjectsCustomAttributesQuery } from '@components/widgets/__generated__/StixCoreObjectsCustomAttributesQuery.graphql';
import useQueryLoading from '../../../utils/hooks/useQueryLoading';
import { getCustomAttributesColumns } from '@components/widgets/WidgetListsDefaultColumns';

export const stixCoreObjectsCustomAttributesQuery = graphql`
  query StixCoreObjectsCustomAttributesQuery($id: String!) {
    stixCoreObject(id: $id) {
      id
      entity_type
      created_at
      creators {
        id
        name
      }
      ... on StixDomainObject {
        created
        modified
        confidence
        standard_id
        status {
          id
          order
          template {
            name
            color
          }
        }
        workflowEnabled
      }
      ... on Campaign {
        name
        description
        aliases
        confidence
        revoked
        objective
      }
      createdBy {
        ... on Identity {
          id
          name
          entity_type
        }
      }
      objectLabel {
        id
        value
        color
      }
      objectMarking {
        id
        definition_type
        definition
        x_opencti_order
        x_opencti_color
      }
      }
  }
`;

interface StixCoreObjectsCustomAttributesContentProps {
  queryRef: PreloadedQuery<StixCoreObjectsCustomAttributesQuery>;
  columns: readonly WidgetColumn[];
  layout: WidgetColumnsLayout;
}

const StixCoreObjectsCustomAttributesContent = ({
  queryRef,
  columns,
  layout,
}: StixCoreObjectsCustomAttributesContentProps) => {
  const data = usePreloadedQuery(stixCoreObjectsCustomAttributesQuery, queryRef);

  if (!data?.stixCoreObject) return <WidgetNoData />;

  return (
    <WidgetCustomAttributes
      data={data.stixCoreObject}
      columns={columns}
      layout={layout}
    />
  );
};

interface StixCoreObjectsCustomAttributesProps {
  title?: string;
  variant?: string;
  height?: number;
  startDate?: string;
  endDate?: string;
  dataSelection: object[];
  widgetId: string;
  parameters?: WidgetParameters;
  popover?: React.ReactNode;
  host?: WidgetHost;
}

const StixCoreObjectsCustomAttributes = ({
  title,
  variant,
  height,
  dataSelection,
  parameters = {},
  popover,
  host,
}: StixCoreObjectsCustomAttributesProps) => {
  const { t_i18n } = useFormatter();
  const rootRef = useRef(null);

  const { resolvedDataSelection, isPreviewMode } = useDashboardViz({
    perspective: 'entities',
    dataSelection,
    host,
  });

  const selection = resolvedDataSelection[0];
  const layout: WidgetColumnsLayout = (selection.layout as WidgetColumnsLayout) ?? '1';

  const resolvedEntityId = host?.kind === 'custom-view' ? host.customViewTargetEntityId : undefined;
  const entityType = host?.kind === 'custom-view' ? host.customViewTargetEntityType : undefined;

  const columns = (selection.columns && selection.columns.length > 0)
    ? selection.columns as readonly WidgetColumn[]
    : getCustomAttributesColumns(entityType);

  const queryRef = useQueryLoading<StixCoreObjectsCustomAttributesQuery>(
    stixCoreObjectsCustomAttributesQuery,
    { id: resolvedEntityId ?? '' },
  );

  return (
    <WidgetContainer
      padding="horizontal"
      height={height}
      title={parameters.title ?? title ?? t_i18n('Custom attributes')}
      variant={variant}
      action={popover}
      showPreviewTag={isPreviewMode}
    >
      <div ref={rootRef} style={{ height: '100%', overflowY: 'auto' }}>
        {!resolvedEntityId
          ? <WidgetNoHostEntity host={host} />
          : queryRef
            ? (
                <React.Suspense fallback={<Loader variant={LoaderVariant.inElement} />}>
                  <StixCoreObjectsCustomAttributesContent
                    queryRef={queryRef}
                    columns={columns}
                    layout={layout}
                  />
                </React.Suspense>
              )
            : <Loader variant={LoaderVariant.inElement} />}
      </div>
    </WidgetContainer>
  );
};

export default StixCoreObjectsCustomAttributes;
