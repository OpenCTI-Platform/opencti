import { Route, Routes, useParams } from 'react-router-dom';
import { FintelDesignQuery } from '@components/settings/fintel_design/__generated__/FintelDesignQuery.graphql';
import React, { FunctionComponent } from 'react';
import { graphql, PreloadedQuery, usePreloadedQuery } from 'react-relay';
import FintelDesign from '@components/settings/fintel_design/FintelDesign';
import Loader, { LoaderVariant } from '../../../../components/Loader';
import useQueryLoading from '../../../../utils/hooks/useQueryLoading';
import { useFormatter } from '../../../../components/i18n';
import { SETTINGS_SETCUSTOMIZATION } from '../../../../utils/hooks/useGranted';
import Security from '../../../../utils/Security';
import CustomizationMenu from '../CustomizationMenu';
import Breadcrumbs from '../../../../components/Breadcrumbs';
import ErrorNotFound from '../../../../components/ErrorNotFound';

const fintelDesignQuery = graphql`
  query FintelDesignQuery($id: String!) {
    fintelDesign(id: $id) {
      id
      name
      ...FintelDesign_fintelDesign
    }
  }
`;

interface RootFintelDesignComponentProps {
  queryRef: PreloadedQuery<FintelDesignQuery>
}

const RootFintelDesignComponent: FunctionComponent<RootFintelDesignComponentProps> = ({ queryRef }) => {
  const { t_i18n } = useFormatter();
  const queryData = usePreloadedQuery(fintelDesignQuery, queryRef);
  const { fintelDesign } = queryData;

  return (
    <Security needs={[SETTINGS_SETCUSTOMIZATION]}>
      <>
        {fintelDesign ? (
          <>
            <CustomizationMenu />
            <Breadcrumbs elements={[
              { label: t_i18n('Settings') },
              { label: t_i18n('Customization') },
              { label: t_i18n('Fintel Designs') },
              { label: fintelDesign.name, current: true },
            ]}
            />
            <Routes>
              <Route
                path="/"
                element={<FintelDesign fintelDesignData={fintelDesign} />}
              />
            </Routes>
          </>
        ) : (
          <ErrorNotFound />
        )
      }
      </>
    </Security>
  );
};

const RootFintelDesign = () => {
  const { fintelDesignId } = useParams() as { fintelDesignId: string };
  if (!fintelDesignId) return null;
  const queryRef = useQueryLoading<FintelDesignQuery>(
    fintelDesignQuery,
    { id: fintelDesignId },
  );
  console.log('fintelDesignId', fintelDesignId);
  return queryRef ? (
    <React.Suspense fallback={<Loader variant={LoaderVariant.container} />}>
      <RootFintelDesignComponent queryRef={queryRef} />
    </React.Suspense>
  ) : (
    <Loader variant={LoaderVariant.container} />
  );
};

export default RootFintelDesign;
