import React, { ReactNode } from 'react';
import type { WidgetHost } from '../../../../utils/widget/widget';
import useGranted, { INGESTION, MODULES } from '../../../../utils/hooks/useGranted';
import WidgetRenderContent from '../../../../components/dashboard/WidgetRenderContent';

interface SourcesWidgetRenderContentProps {
  isMissingHostEntity: boolean;
  isMissingSavedFilters: boolean;
  queryRef: unknown;
  host?: WidgetHost;
  children: ReactNode;
}

/**
 * Guard of the "Intelligence sources" widgets: source scorecards are readable with the connectors or ingestion capability.
 */
const SourcesWidgetRenderContent = ({ isMissingHostEntity, isMissingSavedFilters, queryRef, host, children }: SourcesWidgetRenderContentProps) => {
  const isGranted = useGranted([MODULES, INGESTION]);
  return (
    <WidgetRenderContent
      isMissingHostEntity={isMissingHostEntity}
      isMissingSavedFilters={isMissingSavedFilters}
      isGranted={isGranted}
      queryRef={queryRef}
      host={host}
    >
      {children}
    </WidgetRenderContent>
  );
};

export default SourcesWidgetRenderContent;
