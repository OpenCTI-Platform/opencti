import React, { ReactNode } from 'react';
import type { WidgetHost } from '../../../../utils/widget/widget';
import useGranted, { INGESTION, MODULES } from '../../../../utils/hooks/useGranted';
import WidgetRenderContent, { type WidgetRenderGuards } from '../../../../components/dashboard/WidgetRenderContent';

interface SourcesWidgetRenderContentProps extends WidgetRenderGuards {
  queryRef: unknown;
  host?: WidgetHost;
  children: ReactNode;
}

/**
 * Guard of the "Intelligence sources" widgets: source scorecards are readable with the connectors or ingestion capability.
 */
const SourcesWidgetRenderContent = ({ queryRef, host, children, ...renderGuards }: SourcesWidgetRenderContentProps) => {
  const isGranted = useGranted([MODULES, INGESTION]);
  return (
    <WidgetRenderContent
      {...renderGuards}
      isGranted={isGranted}
      queryRef={queryRef}
      host={host}
    >
      {children}
    </WidgetRenderContent>
  );
};

export default SourcesWidgetRenderContent;
