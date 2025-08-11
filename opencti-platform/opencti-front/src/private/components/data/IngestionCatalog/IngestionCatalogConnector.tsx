import { useParams } from 'react-router-dom';
import { graphql, PreloadedQuery, usePreloadedQuery } from 'react-relay';
import React, { Suspense } from 'react';
import IngestionCatalogConnectorHeader from '@components/data/IngestionCatalog/IngestionCatalogConnectorHeader';
import IngestionCatalogConnectorOverview from '@components/data/IngestionCatalog/IngestionCatalogConnectorOverview';
import { IngestionCatalogConnectorQuery } from '@components/data/IngestionCatalog/__generated__/IngestionCatalogConnectorQuery.graphql';
import Breadcrumbs from '../../../../components/Breadcrumbs';
import Loader, { LoaderVariant } from '../../../../components/Loader';
import useQueryLoading from '../../../../utils/hooks/useQueryLoading';
import { useFormatter } from '../../../../components/i18n';
import useConnectedDocumentModifier from '../../../../utils/hooks/useConnectedDocumentModifier';
import ErrorNotFound from '../../../../components/ErrorNotFound';

const ingestionCatalogConnectorQuery = graphql`
  query IngestionCatalogConnectorQuery($slug: String!) {
    contract(slug: $slug) {
      catalog_id
      contract
    }
  }
`;

interface IngestionCatalogConnectorComponentProps {
  queryRef: PreloadedQuery<IngestionCatalogConnectorQuery>;
}

const IngestionCatalogConnectorComponent = ({
  queryRef,
}: IngestionCatalogConnectorComponentProps) => {
  const { t_i18n } = useFormatter();
  const { setTitle } = useConnectedDocumentModifier();
  setTitle(t_i18n('Catalog | Ingestion | Data'));

  const { contract } = usePreloadedQuery(
    ingestionCatalogConnectorQuery,
    queryRef,
  );
  if (!contract) return <ErrorNotFound />;
  const connector = JSON.parse(contract.contract);

  return (
    <>
      <Breadcrumbs elements={[
        { label: t_i18n('Data') },
        { label: t_i18n('Ingestion') },
        { label: t_i18n('Catalog'), link: '/dashboard/data/ingestion/catalog' },
        { label: connector.default.CONNECTOR_NAME, current: true },
      ]}
      />
      <IngestionCatalogConnectorHeader connector={connector} catalogId={contract.catalog_id} />
      <IngestionCatalogConnectorOverview connector={connector} />
    </>
  );
};

const IngestionCatalogConnector = () => {
  const { connectorSlug } = useParams();
  const queryRef = useQueryLoading<IngestionCatalogConnectorQuery>(
    ingestionCatalogConnectorQuery,
    { slug: connectorSlug ?? '' },
  );
  return (
    <Suspense fallback={<Loader variant={LoaderVariant.container} />}>
      {queryRef && <IngestionCatalogConnectorComponent queryRef={queryRef} />}
    </Suspense>
  );
};

export default IngestionCatalogConnector;
