import React, { Suspense } from 'react';
import IngestionMenu from '@components/data/IngestionMenu';
import { graphql, PreloadedQuery, usePreloadedQuery } from 'react-relay';
import { IngestionCatalogQuery } from '@components/data/__generated__/IngestionCatalogQuery.graphql';
import IngestionCatalogCard from '@components/data/IngestionCatalog/IngestionCatalogCard';
import Breadcrumbs from '../../../components/Breadcrumbs';
import { useFormatter } from '../../../components/i18n';
import useConnectedDocumentModifier from '../../../utils/hooks/useConnectedDocumentModifier';
import PageContainer from '../../../components/PageContainer';
import Loader, { LoaderVariant } from '../../../components/Loader';
import useQueryLoading from '../../../utils/hooks/useQueryLoading';
import ListCardsContent from '../../../components/list_cards/ListCardsContent';

export const ingestionCatalogQuery = graphql`
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
    queryRef,
  );

  const contracts: string[] = catalogs.flatMap((catalog) => catalog.contracts);

  return (
    <>
      <IngestionMenu />
      <PageContainer withRightMenu withGap>
        <Breadcrumbs elements={[{ label: t_i18n('Data') }, { label: t_i18n('Ingestion') }, { label: t_i18n('Catalog'), current: true }]} />
        {contracts.length > 0 && (
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
  return (
    <Suspense fallback={<Loader variant={LoaderVariant.container} />}>
      {queryRef && <IngestionCatalogComponent queryRef={queryRef} />}
    </Suspense>
  );
};

export default IngestionCatalog;
