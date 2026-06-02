import React, { useRef } from 'react';
import { graphql } from 'react-relay';
import { WidgetColumn, WidgetHost, type WidgetParameters } from '../../../utils/widget/widget';
import { useFormatter } from '../../../components/i18n';
import useDashboardViz from '../../../components/dashboard/useDashboardViz';
import { WidgetColumnsLayout } from '@components/widgets/WidgetCustomAttributesColumnsInput';
import WidgetContainer from '../../../components/dashboard/WidgetContainer';
import WidgetNoHostEntity from '../../../components/dashboard/WidgetNoHostEntity';
import { QueryRenderer } from '../../../relay/environment';
import WidgetCustomAttributes from '@components/widgets/WidgetCustomAttribute';
import WidgetNoData from '../../../components/dashboard/WidgetNoData';
import Loader, { LoaderVariant } from '../../../components/Loader';
import { StixCoreObjectsCustomAttributesQuery$data } from '@components/widgets/__generated__/StixCoreObjectsCustomAttributesQuery.graphql';

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
  entityId?: string;
}

const StixCoreObjectsCustomAttributes = ({
  title,
  variant,
  height,
  dataSelection,
  parameters = {},
  popover,
  host,
  entityId,
}: StixCoreObjectsCustomAttributesProps) => {
  const { t_i18n } = useFormatter();
  const { resolvedDataSelection, isMissingHostEntity, isPreviewMode } = useDashboardViz({
    perspective: 'entities',
    dataSelection,
    host,
  });

  const selection = resolvedDataSelection[0];
  const columns = selection.columns ?? [];
  const layout: WidgetColumnsLayout = (selection.layout as WidgetColumnsLayout) ?? '1';

  const resolvedEntityId = entityId ?? selection.instance_id ?? null;

  const rootRef = useRef(null);

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
        {isMissingHostEntity
          ? <WidgetNoHostEntity host={host} />
          : !resolvedEntityId
              ? (
                  <WidgetCustomAttributes
                    data={null}
                    columns={columns as WidgetColumn[]}
                    layout={layout}
                  />
                )
              : (
                  <QueryRenderer
                    query={stixCoreObjectsCustomAttributesQuery}
                    variables={{ id: resolvedEntityId }}
                    render={({ props }: { props: StixCoreObjectsCustomAttributesQuery$data }) => {
                      if (props?.stixCoreObject) {
                        const node = props.stixCoreObject;
                        return (
                          <WidgetCustomAttributes
                            data={node}
                            columns={columns as WidgetColumn[]}
                            layout={layout}
                          />
                        );
                      }
                      if (props) {
                        return <WidgetNoData />;
                      }
                      return <Loader variant={LoaderVariant.inElement} />;
                    }}
                  />
                )}
      </div>
    </WidgetContainer>
  );
};

export default StixCoreObjectsCustomAttributes;
