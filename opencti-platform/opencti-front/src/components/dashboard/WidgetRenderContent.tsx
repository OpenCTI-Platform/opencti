import React, { ReactNode, Suspense } from 'react';
import Loader, { LoaderVariant } from '../Loader';
import WidgetNoHostEntity from './WidgetNoHostEntity';
import WidgetNoSavedFilters from './WidgetNoSavedFilters';
import WidgetAccessDenied from './WidgetAccessDenied';
import WidgetNoData from './WidgetNoData';
import type { WidgetHost } from '../../utils/widget/widget';

/**
 * Conditions under which a widget cannot run its query safely.
 * Returned as a whole by useDashboardViz so widgets can forward them with a spread.
 */
export interface WidgetRenderGuards {
  isMissingHostEntity: boolean;
  isMissingSavedFilters: boolean;
  hasUnresolvedVariables: boolean;
}

interface WidgetRenderContentProps extends WidgetRenderGuards {
  queryRef: unknown;
  host?: WidgetHost;
  isGranted?: boolean;
  children: ReactNode;
}

/**
 * Generic guard component for dashboard widgets.
 *
 * Handles the common guard checks (missing host entity, missing saved filters,
 * unresolved dashboard variables, access denied, loading state) and wraps children in a Suspense boundary
 * when all guards pass.
 */
const WidgetRenderContent = ({
  isMissingHostEntity,
  isMissingSavedFilters,
  hasUnresolvedVariables,
  isGranted,
  queryRef,
  host,
  children,
}: WidgetRenderContentProps) => {
  if (isMissingHostEntity) {
    return <WidgetNoHostEntity host={host} />;
  }

  if (isMissingSavedFilters) {
    return <WidgetNoSavedFilters />;
  }

  if (hasUnresolvedVariables) {
    return <WidgetNoData />;
  }

  if (isGranted === false) {
    return <WidgetAccessDenied />;
  }

  if (!queryRef) {
    return <Loader variant={LoaderVariant.inElement} />;
  }

  return (
    <Suspense fallback={<Loader variant={LoaderVariant.inElement} />}>
      {children}
    </Suspense>
  );
};

export default WidgetRenderContent;
