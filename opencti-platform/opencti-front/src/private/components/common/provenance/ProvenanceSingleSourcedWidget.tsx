import React, { ReactNode } from 'react';
import { graphql, PreloadedQuery, usePreloadedQuery } from 'react-relay';
import { useFormatter } from '../../../../components/i18n';
import WidgetContainer from '../../../../components/dashboard/WidgetContainer';
import WidgetHorizontalBars from '../../../../components/dashboard/WidgetHorizontalBars';
import WidgetNoData from '../../../../components/dashboard/WidgetNoData';
import WidgetRenderContent from '../../../../components/dashboard/WidgetRenderContent';
import useDashboardViz from '../../../../components/dashboard/useDashboardViz';
import type { DashboardConfig } from '../../../../components/dashboard/dashboard-types';
import useEntityTranslation from '../../../../utils/hooks/useEntityTranslation';
import type { Widget, WidgetDataSelection, WidgetHost, WidgetParameters, WidgetPerspective } from '../../../../utils/widget/widget';
import { buildProvenanceWidgetVariables } from './provenanceWidgetUtils';
import { ProvenanceSingleSourcedWidgetQuery } from './__generated__/ProvenanceSingleSourcedWidgetQuery.graphql';

const provenanceSingleSourcedWidgetQuery = graphql`
  query ProvenanceSingleSourcedWidgetQuery($types: [String!], $filters: FilterGroup) {
    provenanceSingleSourcedByType(types: $types, filters: $filters) {
      entity_type
      total
      single_sourced
    }
  }
`;

const DEFAULT_MAX_TYPES = 10;

const ProvenanceSingleSourcedWidgetComponent = ({ queryRef, limit }: { queryRef: PreloadedQuery<ProvenanceSingleSourcedWidgetQuery>; limit: number }) => {
  const { t_i18n } = useFormatter();
  const { translateEntityType } = useEntityTranslation();
  const { provenanceSingleSourcedByType } = usePreloadedQuery(provenanceSingleSourcedWidgetQuery, queryRef);
  const byType = provenanceSingleSourcedByType.slice(0, limit);
  if (byType.length === 0) {
    return <WidgetNoData />;
  }
  return (
    <div data-testid="provenance-single-sourced-widget" style={{ height: '100%' }}>
      <WidgetHorizontalBars
        series={[
          { name: t_i18n('Single sourced'), data: byType.map((entry) => entry.single_sourced) },
          { name: t_i18n('Corroborated'), data: byType.map((entry) => entry.total - entry.single_sourced) },
        ]}
        categories={byType.map((entry) => translateEntityType(entry.entity_type))}
        stacked
        legend
      />
    </div>
  );
};

interface ProvenanceSingleSourcedWidgetProps {
  perspective: WidgetPerspective;
  dataSelection: Widget['dataSelection'];
  parameters?: WidgetParameters | null;
  variant?: string;
  height?: number;
  popover?: ReactNode;
  host?: WidgetHost;
  config: DashboardConfig;
  refreshRate?: number | null;
}

/**
 * Widget of the catalog: per type, the knowledge asserted by a single source against the corroborated knowledge.
 */
const ProvenanceSingleSourcedWidget = ({
  perspective,
  dataSelection,
  parameters,
  variant,
  height,
  popover,
  host,
  config,
  refreshRate = null,
}: ProvenanceSingleSourcedWidgetProps) => {
  const { t_i18n } = useFormatter();
  const { resolvedDataSelection, isMissingHostEntity, isMissingSavedFilters, isPreviewMode, queryRef } = useDashboardViz<ProvenanceSingleSourcedWidgetQuery>({
    perspective,
    dataSelection,
    host,
    refreshRate,
    query: provenanceSingleSourcedWidgetQuery,
    config,
    buildQueryVariables: (selection: WidgetDataSelection[], dashboardConfig: DashboardConfig) => buildProvenanceWidgetVariables(perspective, selection, dashboardConfig),
  });
  return (
    <WidgetContainer
      padding="small"
      height={height}
      title={parameters?.title ?? t_i18n('Single sourced share by type')}
      variant={variant}
      action={popover}
      showPreviewTag={isPreviewMode}
    >
      <WidgetRenderContent
        isMissingHostEntity={isMissingHostEntity}
        isMissingSavedFilters={isMissingSavedFilters}
        queryRef={queryRef}
        host={host}
      >
        {resolvedDataSelection.length > 0 && (
          <ProvenanceSingleSourcedWidgetComponent queryRef={queryRef!} limit={resolvedDataSelection[0].number ?? DEFAULT_MAX_TYPES} />
        )}
      </WidgetRenderContent>
    </WidgetContainer>
  );
};

export default ProvenanceSingleSourcedWidget;
