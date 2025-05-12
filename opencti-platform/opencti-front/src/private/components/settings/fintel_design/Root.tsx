import { Route, Routes, useParams } from 'react-router-dom';
import React, { FunctionComponent } from 'react';
import { graphql, PreloadedQuery, usePreloadedQuery } from 'react-relay';
import FintelDesign from '@components/settings/fintel_design/FintelDesign';
import { RootFintelDesignQuery } from '@components/settings/fintel_design/__generated__/RootFintelDesignQuery.graphql';
import Loader, { LoaderVariant } from '../../../../components/Loader';
import useQueryLoading from '../../../../utils/hooks/useQueryLoading';
import { useFormatter } from '../../../../components/i18n';
import { SETTINGS_SETCUSTOMIZATION } from '../../../../utils/hooks/useGranted';
import Security from '../../../../utils/Security';
import CustomizationMenu from '../CustomizationMenu';
import Breadcrumbs from '../../../../components/Breadcrumbs';
import ErrorNotFound from '../../../../components/ErrorNotFound';

const fintelDesignQuery = graphql`
  query RootFintelDesignQuery($id: String!) {
    fintelDesign(id: $id) {
      id
      name
      ...FintelDesign_fintelDesign
      ...FintelDesignsLine_node
    }
  }
`;

interface RootFintelDesignComponentProps {
  queryRef: PreloadedQuery<RootFintelDesignQuery>
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
              { label: t_i18n('Fintel Designs'), link: '/dashboard/settings/customization/fintel_design' },
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
  const queryRef = useQueryLoading<RootFintelDesignQuery>(
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
