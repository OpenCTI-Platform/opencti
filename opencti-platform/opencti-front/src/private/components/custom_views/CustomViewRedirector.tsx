import { ReactNode, useMemo } from 'react';
import { Navigate, useParams } from 'react-router-dom';
import CustomView from './CustomView';
import { useCustomViews } from './useCustomViews';
import type { CustomView as CustomViewType } from './CustomViews-types';
import SlugRedirectHandler, { type SlugRedirectHandlerPageInfo } from '../../../components/SlugRedirectHandler';

interface CustomViewRedirectorProps {
  entity: { id: string; entity_type: string };
  Fallback: ReactNode;
  indexFallback: ReactNode;
}

const renderMatch = (entity: { id: string; entity_type: string }) => {
  // eslint-disable-next-line react/display-name
  return (info: SlugRedirectHandlerPageInfo) => {
    return <CustomView customViewId={(info as CustomViewType).id} entityId={entity.id} entityType={entity.entity_type} />;
  };
};

const CustomViewRedirector = ({ entity, Fallback, indexFallback }: CustomViewRedirectorProps) => {
  const { customViews } = useCustomViews(entity.entity_type);
  const pagesInfo = useMemo(() => customViews.reduce(
    (acc, customViewInfo) => ({
      ...acc,
      [customViewInfo.id.replaceAll('-', '')]: customViewInfo,
    }), {} as Record<string, CustomViewType>,
  ), [customViews]);
  const { '*': splat } = useParams();
  if (splat === '') {
    const defaultCustomView = customViews.find((customView) => customView.default);
    if (defaultCustomView) {
      return <Navigate to={defaultCustomView.path} replace />;
    }
    return indexFallback;
  }
  return (
    <SlugRedirectHandler
      renderMatch={renderMatch(entity)}
      NoMatch={Fallback}
      pagesInfo={pagesInfo}
    />
  );
};

export default CustomViewRedirector;
