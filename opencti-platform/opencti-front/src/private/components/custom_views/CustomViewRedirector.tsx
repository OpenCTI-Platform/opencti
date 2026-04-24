import { ReactNode, useMemo } from 'react';
import RootCustomView from './RootCustomView';
import { useCustomViews } from './useCustomViews';
import type { CustomView } from './CustomViews-types';
import SlugRedirectHandler, { type SlugRedirectHandlerPageInfo } from '../../../components/SlugRedirectHandler';

interface CustomViewRedirectorProps {
  entityType: string;
  Fallback: ReactNode;
}

const renderMatch = (info: SlugRedirectHandlerPageInfo) =>
  <RootCustomView customViewId={(info as CustomView).id} />;

const CustomViewRedirector = ({ entityType, Fallback }: CustomViewRedirectorProps) => {
  const { customViews } = useCustomViews(entityType);
  const pagesInfo = useMemo(() => customViews.reduce(
    (acc, customViewInfo) => ({
      ...acc,
      [customViewInfo.id.replaceAll('-', '')]: customViewInfo,
    }), {} as Record<string, CustomView>,
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
