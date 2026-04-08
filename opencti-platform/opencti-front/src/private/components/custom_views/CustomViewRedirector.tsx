import { ReactNode, useMemo } from 'react';
import RootCustomView from './RootCustomView';
import { useCustomViews } from './useCustomViews';
import { CustomViewsInfo } from './types';
import SlugRedirectHandler, { type SlugRedirectHandlerPageInfo } from '../../../components/SlugRedirectHandler';

interface CustomViewRedirectorProps {
  entityType: string;
  Fallback: ReactNode;
}

const renderMatch = (info: SlugRedirectHandlerPageInfo) =>
  <RootCustomView customViewId={(info as CustomViewsInfo[number]).id} />;

const CustomViewRedirector = ({ entityType, Fallback }: CustomViewRedirectorProps) => {
  const { customViews } = useCustomViews(entityType);
  const pagesInfo = useMemo(() => customViews.reduce(
    (acc, customViewInfo) => ({
      ...acc,
      [customViewInfo.id.replaceAll('-', '')]: customViewInfo,
    }), {} as Record<string, CustomViewsInfo[number]>,
  ), [customViews]);
  return (
    <SlugRedirectHandler
      renderMatch={renderMatch}
      NoMatch={Fallback}
      pagesInfo={pagesInfo}
    />
  );
};

export default CustomViewRedirector;
