import { graphql, usePreloadedQuery, useQueryLoader } from 'react-relay';
import { Link, Navigate, Route, Routes, useLocation, useParams } from 'react-router-dom';
import React, { FunctionComponent, Suspense, useEffect } from 'react';
import { RootFintelDesignQuery, RootFintelDesignQuery$data } from '@components/settings/fintel_design/__generated__/RootFintelDesignQuery.graphql';
import { useFormatter } from '../../../../components/i18n';
import Loader, { LoaderVariant } from '../../../../components/Loader';
import FintelDesign from './FintelDesign';
import Breadcrumbs from '../../../../components/Breadcrumbs';

const fintelDesignQuery = graphql`
  query RootFintelDesignQuery($id: ID!) {
    fintelDesign(id: $id) {
      ...FintelDesign_fintelDesign
    }
  }
`;

interface RootFintelDesignComponentProps {
  fintelDesignId: string;
  queryRef: RootFintelDesignQuery$data;
}

const RootFintelDesignComponent: FunctionComponent<RootFintelDesignComponentProps> = ({ fintelDesignId, queryRef }) => {
  const { t_i18n } = useFormatter();

  const { fintelDesign } = usePreloadedQuery<RootFintelDesignQuery>(fintelDesignQuery, queryRef);
  return (
    <>
      <Breadcrumbs elements={[
        { label: t_i18n('Settings') },
        { label: t_i18n('Customization') },
        { label: t_i18n('Fintel Designs'), current: true },
      ]}
      />
      <Routes>
        <Route
          path="/"
          element={
            <FintelDesign fintelDesignFragment={fintelDesign} />
          }
        />
      </Routes>
    </>
  );
};

const RootFintelDesign = () => {
  const { fintelDesignId } = useParams() as { fintelDesignId: string };
  const [queryRef, loadQuery] = useQueryLoader<RootFintelDesignQuery>(fintelDesignQuery);
  useEffect(() => {
    loadQuery({ id: fintelDesignId }, { fetchPolicy: 'store-and-network' });
  }, []);

  return (
    <>
      {queryRef && (
        <Suspense fallback={<Loader variant={LoaderVariant.container} />}>
          <RootFintelDesignComponent fintelDesignId={fintelDesignId} queryRef={queryRef} />
        </Suspense>
      )}
    </>
  );
};

export default RootFintelDesign;
