import { ReactNode, useMemo } from 'react';
import { Navigate, useParams } from 'react-router-dom';
import CustomView from './CustomView';
import { useCustomViews } from './useCustomViews';
import type { CustomView as CustomViewType } from './CustomViews-types';
import SlugRedirectHandler, { type SlugRedirectHandlerPageInfo } from '../../../components/SlugRedirectHandler';

interface CustomViewRedirectorProps {
  entityType: string;
  Fallback: ReactNode;
  indexFallback: ReactNode;
}

const renderMatch = (info: SlugRedirectHandlerPageInfo) =>
  <CustomView customViewId={(info as CustomViewType).id} />;

const CustomViewRedirector = ({ entityType, Fallback, indexFallback }: CustomViewRedirectorProps) => {
  const { customViews } = useCustomViews(entityType);
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
      renderMatch={renderMatch}
      NoMatch={Fallback}
      pagesInfo={pagesInfo}
    />
  );
};

export default CustomViewRedirector;
