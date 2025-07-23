import { useParams } from 'react-router-dom';
import { PreloadedQuery, usePreloadedQuery } from 'react-relay';
import { ingestionCatalogQuery } from '@components/data/IngestionCatalog';
import { IngestionCatalogQuery } from '@components/data/__generated__/IngestionCatalogQuery.graphql';
import React, { Suspense } from 'react';
import IngestionCatalogConnectorHeader from '@components/data/IngestionCatalog/IngestionCatalogConnectorHeader';
import IngestionCatalogConnectorOverview from '@components/data/IngestionCatalog/IngestionCatalogConnectorOverview';
import { IngestionConnector } from '@components/data/IngestionCatalog/IngestionCatalogCard';
import Breadcrumbs from '../../../../components/Breadcrumbs';
import Loader, { LoaderVariant } from '../../../../components/Loader';
import useQueryLoading from '../../../../utils/hooks/useQueryLoading';
import { useFormatter } from '../../../../components/i18n';
import useConnectedDocumentModifier from '../../../../utils/hooks/useConnectedDocumentModifier';

interface IngestionCatalogConnectorComponentProps {
  queryRef: PreloadedQuery<IngestionCatalogQuery>;
}

export interface IngestionCatalogConnectorConnectorProps {
  connector: IngestionConnector;
}

const IngestionCatalogConnectorComponent = ({
  queryRef,
}: IngestionCatalogConnectorComponentProps) => {
  const { t_i18n } = useFormatter();
  const { setTitle } = useConnectedDocumentModifier();
  setTitle(t_i18n('Catalog | Ingestion | Data'));
  const { connectorId } = useParams();

  const { catalogs } = usePreloadedQuery(
    ingestionCatalogQuery,
    queryRef,
  );

  const findContractByName = () => {
    for (const catalog of catalogs) {
      for (const contractStr of catalog.contracts || []) {
        const contract = JSON.parse(contractStr);
        if (contract.default.CONNECTOR_NAME === connectorId) {
          return contract;
        }
      }
    }
    return null;
  };

  const connector = findContractByName();

  return (
    <>
      <Breadcrumbs elements={[{ label: t_i18n('Data') }, { label: t_i18n('Ingestion') }, { label: t_i18n('Catalog') }, { label: connector.default.CONNECTOR_NAME, current: true }]} />
      <IngestionCatalogConnectorHeader connector={connector} />
      <IngestionCatalogConnectorOverview connector={connector} />
    </>
  );
};

const IngestionCatalogConnector = () => {
  const queryRef = useQueryLoading<IngestionCatalogQuery>(
    ingestionCatalogQuery,
  );
  return (
    <Suspense fallback={<Loader variant={LoaderVariant.container} />}>
      {queryRef && <IngestionCatalogConnectorComponent queryRef={queryRef} />}
    </Suspense>
  );
};

export default IngestionCatalogConnector;
