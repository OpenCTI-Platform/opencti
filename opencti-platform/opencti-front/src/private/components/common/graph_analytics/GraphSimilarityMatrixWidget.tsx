import React, { ReactNode } from 'react';
import { graphql, PreloadedQuery, usePreloadedQuery } from 'react-relay';
import { useFormatter } from '../../../../components/i18n';
import WidgetContainer from '../../../../components/dashboard/WidgetContainer';
import WidgetNoData from '../../../../components/dashboard/WidgetNoData';
import useDashboardViz from '../../../../components/dashboard/useDashboardViz';
import WidgetRenderContent from '../../../../components/dashboard/WidgetRenderContent';
import { computeWidgetFiltersForSelection } from '../../../../components/dashboard/dashboardVizUtils';
import type { DashboardConfig } from '../../../../components/dashboard/dashboard-types';
import type { Widget, WidgetDataSelection, WidgetHost, WidgetParameters } from '../../../../utils/widget/widget';
import GraphSimilarityMatrix from './GraphSimilarityMatrix';
import type { GraphSimilarityMatrixWidgetQuery } from './__generated__/GraphSimilarityMatrixWidgetQuery.graphql';

const graphSimilarityMatrixWidgetQuery = graphql`
  query GraphSimilarityMatrixWidgetQuery($filters: FilterGroup, $first: Int) {
    graphSimilarityMatrix(filters: $filters, first: $first) {
      entities {
        id
        entity_type
        representative {
          main
        }
      }
      cells {
        source_id
        target_id
        score
        shared_count
      }
    }
  }
`;

const DEFAULT_ENTITIES = 10;
const MAX_ENTITIES = 25;

/** The most connected entities of the data selection (typically threats), compared pairwise. */
export const buildGraphSimilarityMatrixVariables = (
  resolvedDataSelection: WidgetDataSelection[],
  config: DashboardConfig,
): GraphSimilarityMatrixWidgetQuery['variables'] => {
  const [selection] = resolvedDataSelection;
  const { filters } = computeWidgetFiltersForSelection(selection, config);
  return {
    filters,
    first: Math.min(MAX_ENTITIES, Math.max(2, selection?.number ?? DEFAULT_ENTITIES)),
  };
};

const GraphSimilarityMatrixComponent = ({ queryRef }: { queryRef: PreloadedQuery<GraphSimilarityMatrixWidgetQuery> }) => {
  const { graphSimilarityMatrix } = usePreloadedQuery(graphSimilarityMatrixWidgetQuery, queryRef);
  if (!graphSimilarityMatrix || graphSimilarityMatrix.entities.length < 2) {
    return <WidgetNoData />;
  }
  return <GraphSimilarityMatrix entities={graphSimilarityMatrix.entities} cells={graphSimilarityMatrix.cells} />;
};

interface GraphSimilarityMatrixWidgetProps {
  variant?: string;
  height?: number;
  dataSelection: Widget['dataSelection'];
  parameters?: WidgetParameters;
  popover?: ReactNode;
  host?: WidgetHost;
  config: DashboardConfig;
  refreshRate?: number | null;
}

/** Dashboard widget: similarity matrix of the selected threats (or any entities with a similarity profile). */
const GraphSimilarityMatrixWidget = ({
  variant,
  height,
  dataSelection,
  parameters = {},
  popover,
  config,
  refreshRate = null,
  host,
}: GraphSimilarityMatrixWidgetProps) => {
  const { t_i18n } = useFormatter();
  const { isMissingHostEntity, isMissingSavedFilters, isPreviewMode, queryRef } = useDashboardViz<GraphSimilarityMatrixWidgetQuery>({
    perspective: 'entities',
    dataSelection,
    host,
    refreshRate,
    query: graphSimilarityMatrixWidgetQuery,
    config,
    parameters,
    buildQueryVariables: buildGraphSimilarityMatrixVariables,
  });
  return (
    <WidgetContainer
      padding="small"
      height={height}
      title={parameters.title ?? t_i18n('Similarity matrix')}
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
        <GraphSimilarityMatrixComponent queryRef={queryRef!} />
      </WidgetRenderContent>
    </WidgetContainer>
  );
};

export default GraphSimilarityMatrixWidget;
