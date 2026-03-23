import { Suspense } from 'react';
import { useParams } from 'react-router-dom';
import { graphql, PreloadedQuery, usePreloadedQuery } from 'react-relay';
import { ErrorBoundary } from '@components/Error';
import Loader from '../../../components/Loader';
import ErrorNotFound from '../../../components/ErrorNotFound';
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
  if (!customViewDisplay) {
    return <ErrorNotFound />;
  }
  if (!customViewDisplay.manifest) {
    throw new Error('Unable to load custom view');
  }

  return (
    <div
      style={{
        overflow: 'auto',
        marginRight: -20,
        paddingRight: 20,
        paddingTop: 5,
        height: '100%',
      }}
    >
      <CustomView manifest={customViewDisplay.manifest} />
    </div>
  );
};

export const RootCustomView = () => {
  const { customViewId } = useParams();
  if (!customViewId) {
    return <ErrorNotFound />;
  }

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
