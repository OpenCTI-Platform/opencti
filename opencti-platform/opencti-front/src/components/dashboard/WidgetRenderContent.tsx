import React, { ReactNode, Suspense } from 'react';
import Loader, { LoaderVariant } from '../Loader';
import WidgetNoHostEntity from './WidgetNoHostEntity';
import WidgetNoSavedFilters from './WidgetNoSavedFilters';
import WidgetAccessDenied from './WidgetAccessDenied';
import type { WidgetHost } from '../../utils/widget/widget';

interface WidgetRenderContentProps {
  isMissingHostEntity: boolean;
  isMissingSavedFilters: boolean;
  queryRef: unknown;
  host?: WidgetHost;
  isGranted?: boolean;
  children: ReactNode;
}

/**
 * Generic guard component for dashboard widgets.
 *
 * Handles the common guard checks (missing host entity, missing saved filters,
 * access denied, loading state) and wraps children in a Suspense boundary
 * when all guards pass.
 */
const WidgetRenderContent = ({
  isMissingHostEntity,
  isMissingSavedFilters,
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
