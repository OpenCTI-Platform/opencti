import { ReactNode, useMemo } from 'react';
import CustomView from './CustomView';
import { useCustomViews } from './useCustomViews';
import type { CustomView as CustomViewType } from './CustomViews-types';
import SlugRedirectHandler, { type SlugRedirectHandlerPageInfo } from '../../../components/SlugRedirectHandler';

interface CustomViewRedirectorProps {
  entityType: string;
  Fallback: ReactNode;
}

const renderMatch = (info: SlugRedirectHandlerPageInfo) =>
  <CustomView customViewId={(info as CustomViewType).id} />;

const CustomViewRedirector = ({ entityType, Fallback }: CustomViewRedirectorProps) => {
  const { customViews } = useCustomViews(entityType);
  const pagesInfo = useMemo(() => customViews.reduce(
    (acc, customViewInfo) => ({
      ...acc,
      [customViewInfo.id.replaceAll('-', '')]: customViewInfo,
    }), {} as Record<string, CustomViewType>,
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
