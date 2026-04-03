import { Suspense } from 'react';
import { graphql, PreloadedQuery, usePreloadedQuery } from 'react-relay';
import { ErrorBoundary } from '@components/Error';
import Loader from '../../../components/Loader';
import useQueryLoading from '../../../utils/hooks/useQueryLoading';
import { RootCustomViewQuery } from './__generated__/RootCustomViewQuery.graphql';
import CustomView from './CustomView';

const customViewQuery = graphql`
  query RootCustomViewQuery($id: String!) {
    customViewDisplay(id: $id) {
      manifest
    }
  }
`;

interface RootCustomViewComponentProps {
  queryRef: PreloadedQuery<RootCustomViewQuery>;
}

const RootCustomViewComponent = ({ queryRef }: RootCustomViewComponentProps) => {
  const { customViewDisplay } = usePreloadedQuery(customViewQuery, queryRef);
  if (!customViewDisplay?.manifest) {
    throw new Error('Unable to load custom view');
  }

  return <CustomView manifest={customViewDisplay.manifest} />;
};

interface RootCustomViewProps {
  customViewId: string;
}

export const RootCustomView = ({ customViewId }: RootCustomViewProps) => {
  const queryRef = useQueryLoading<RootCustomViewQuery>(
    customViewQuery,
    { id: customViewId },
  );

  return (
    <ErrorBoundary>
      <Suspense fallback={<Loader />}>
        {queryRef && <RootCustomViewComponent queryRef={queryRef} />}
      </Suspense>
    </ErrorBoundary>
  );
};

export default RootCustomView;
