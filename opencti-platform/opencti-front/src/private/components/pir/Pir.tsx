import React, { Suspense } from 'react';
import { graphql, usePreloadedQuery } from 'react-relay';
import { useParams } from 'react-router-dom';
import { PirQuery } from '@components/pir/__generated__/PirQuery.graphql';
import { PreloadedQuery } from 'react-relay/relay-hooks/EntryPointTypes';
import PirHeader from '@components/pir/PirHeader';
import PirTabs from '@components/pir/PirTabs';
import PirKnowledge from '@components/pir/PirKnowledge';
import ErrorNotFound from '../../../components/ErrorNotFound';
import useQueryLoading from '../../../utils/hooks/useQueryLoading';
import Loader from '../../../components/Loader';

const pirQuery = graphql`
  query PirQuery($id: ID!) {
    pir(id: $id) {
      ...PirHeaderFragment
      ...PirKnowledgeFragment
    }
  }
`;

interface PirComponentProps {
  queryRef: PreloadedQuery<PirQuery>
}

const PirComponent = ({ queryRef }: PirComponentProps) => {
  const { pir } = usePreloadedQuery(pirQuery, queryRef);
  if (!pir) return <ErrorNotFound/>;

  return (
    <>
      <PirHeader data={pir} />
      <PirTabs>
        {({ index }) => (
          <>
            <div role="tabpanel" hidden={index !== 0}>
              overview
            </div>
            <div role="tabpanel" hidden={index !== 1}>
              <PirKnowledge data={pir} />
            </div>
            <div role="tabpanel" hidden={index !== 2}>
              ttps
            </div>
            <div role="tabpanel" hidden={index !== 3}>
              analyses
            </div>
          </>
        )}
      </PirTabs>
    </>
  );
};

const Pir = () => {
  const { pirId } = useParams() as { pirId?: string };
  if (!pirId) return <ErrorNotFound/>;

  const pirQueryRef = useQueryLoading<PirQuery>(pirQuery, { id: pirId });

  return (
    <Suspense fallback={<Loader />}>
      {pirQueryRef && <PirComponent queryRef={pirQueryRef} />}
    </Suspense>
  );
};

export default Pir;
