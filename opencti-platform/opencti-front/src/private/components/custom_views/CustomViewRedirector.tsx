import { ReactNode, useMemo } from 'react';
import RootCustomView from './Root';
import { useCustomViews } from './useCustomViews';
import { CustomViewsInfo } from './types';
import NotionLikeRedirector, { type NotionLikePageInfo } from '../../../components/NotionLikeRedirector';

interface CustomViewRedirectorProps {
  entityType: string;
  Fallback: ReactNode;
}

const renderMatch = (info: NotionLikePageInfo) =>
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
    <NotionLikeRedirector
      renderMatch={renderMatch}
      NoMatch={Fallback}
      pagesInfo={pagesInfo}
    />
  );
};

export default CustomViewRedirector;
