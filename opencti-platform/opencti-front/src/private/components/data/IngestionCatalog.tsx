import React from 'react';
import Breadcrumbs from '../../../components/Breadcrumbs';
import IngestionMenu from '@components/data/IngestionMenu';
import { useFormatter } from '../../../components/i18n';
import useConnectedDocumentModifier from '../../../utils/hooks/useConnectedDocumentModifier';
import PageContainer from '../../../components/PageContainer';
import Loader, { LoaderVariant } from '../../../components/Loader';
import { graphql, PreloadedQuery, usePreloadedQuery } from 'react-relay';
import useQueryLoading from '../../../utils/hooks/useQueryLoading';
import { IngestionCatalogQuery } from '@components/data/__generated__/IngestionCatalogQuery.graphql';
import IngestionCatalogCard from '@components/data/IngestionCatalog/IngestionCatalogCard';
import ListCardsContent from '../../../components/list_cards/ListCardsContent';

const ingestionCatalogQuery = graphql`
  query IngestionCatalogQuery {
    catalogs {
      id
      name
      description
      entity_type
      contracts
    }
  }
`;

interface IngestionCatalogComponentProps {
  queryRef: PreloadedQuery<IngestionCatalogQuery>;
}

const IngestionCatalogComponent = ({
  queryRef,
}: IngestionCatalogComponentProps) => {
  const { t_i18n } = useFormatter();
  const { setTitle } = useConnectedDocumentModifier();
  setTitle(t_i18n('Catalog | Ingestion | Data'));
  const { catalogs } = usePreloadedQuery(
    ingestionCatalogQuery,
    queryRef
  );
  const contracts: string[] = [];
  for (const catalog of catalogs) {
    catalog.contracts.map(contract => {
      contracts.push(contract);
    });
  }
  // for (const catalog of catalogs) {
  //   catalog.contracts.map(contract => {
  //     contracts.push(contract);
  //   });
  // }
  // for (const catalog of catalogs) {
  //   catalog.contracts.map(contract => {
  //     contracts.push(contract);
  //   });
  // }

  return (
    <>
      <IngestionMenu />
      <PageContainer withRightMenu withGap>
        <Breadcrumbs elements={[{ label: t_i18n('Data') }, { label: t_i18n('Ingestion') }, { label: t_i18n('Catalog'), current: true }]} />
        {contracts.length && (
          <ListCardsContent
            hasMore={() => false}
            isLoading={() => false}
            dataList={contracts}
            globalCount={contracts.length}
            CardComponent={IngestionCatalogCard}
            rowHeight={350}
          />
        )}
      </PageContainer>
    </>
  );
};

const IngestionCatalog = () => {
  const queryRef = useQueryLoading<IngestionCatalogQuery>(
    ingestionCatalogQuery,
  );
  return queryRef ? (
    <React.Suspense fallback={<Loader variant={LoaderVariant.container} />}>
      <IngestionCatalogComponent
        queryRef={queryRef}
      />
    </React.Suspense>
  ) : (
    <Loader variant={LoaderVariant.container} />
  );
};

export default IngestionCatalog;
