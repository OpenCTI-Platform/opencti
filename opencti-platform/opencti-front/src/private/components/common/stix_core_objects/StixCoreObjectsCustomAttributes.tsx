import React, { useRef } from 'react';
import { graphql, PreloadedQuery, usePreloadedQuery } from 'react-relay';
import { WidgetColumn, WidgetDataSelection, WidgetHost, type WidgetParameters } from '../../../../utils/widget/widget';
import { useFormatter } from '../../../../components/i18n';
import { WidgetColumnsLayout } from '@components/widgets/WidgetCustomAttributesColumnsInput';
import WidgetContainer from '../../../../components/dashboard/WidgetContainer';
import WidgetNoHostEntity from '../../../../components/dashboard/WidgetNoHostEntity';
import WidgetCustomAttributes from '@components/widgets/WidgetCustomAttribute';
import WidgetNoData from '../../../../components/dashboard/WidgetNoData';
import Loader, { LoaderVariant } from '../../../../components/Loader';
import useQueryLoading from '../../../../utils/hooks/useQueryLoading';
import { getCustomAttributesColumns } from '@components/widgets/WidgetListsDefaultColumns';
import { StixCoreObjectsCustomAttributesQuery } from '@components/common/stix_core_objects/__generated__/StixCoreObjectsCustomAttributesQuery.graphql';

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
        confidence
        revoked
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
      ... on Report {
        name
        description
        report_types
        content
        objectAssignee {
          id
          name
          entity_type
        }
        objectParticipant {
          id
          name
          entity_type
        }
      }
      ... on Grouping {
        name
        description
        context
        content
      }
      ... on Campaign {
        name
        description
        aliases
        confidence
        revoked
        objective
        first_seen
        last_seen
      }
      ... on MalwareAnalysis {
        product
        result_name
        result
        submitted
        analysis_started
        analysis_ended
        version
        configuration_version 
        analysis_engine_version
        analysis_definition_version
        modules
        confidence
        revoked
        operatingSystem {
          id
          name
          entity_type
        }
        configuration_version
        objectAssignee {
          id
          name
          entity_type
        }
      }
      ... on CaseIncident {
        name
        description
        priority
        severity
        response_types
        objectAssignee {
          name
          id
        }
        objectParticipant {
          name
          id
        }
      }
      ... on CaseRfi {
        name
        description
        priority
        severity
        information_types
        content
        objectAssignee {
          name
          id
        }
        objectParticipant {
          name
          id
        }
      }
      ... on CaseRft {
        name
        description
        priority
        severity
        takedown_types
        content
        objectAssignee {
          name
          id
        }
        objectParticipant {
          name
          id
        }
      }
      ... on Incident {
        name
        description
        objectParticipant {
          id
            name
        }
        objectAssignee {
          id
          name
        }
        incident_type
        severity
        source
        objective
        first_seen
        last_seen
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
  dataSelection: WidgetDataSelection[];
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
  const isPreviewMode = host?.kind === 'custom-view'
    && Boolean(host.customViewTargetEntityId)
    && host.previewMode;

  const selection = (dataSelection as WidgetDataSelection[])[0];
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
