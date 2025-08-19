import React, { Suspense, useEffect, useState } from 'react';
import IngestionMenu from '@components/data/IngestionMenu';
import { graphql, PreloadedQuery, usePreloadedQuery } from 'react-relay';
import { IngestionCatalogQuery } from '@components/data/__generated__/IngestionCatalogQuery.graphql';
import IngestionCatalogCard, { IngestionConnectorType } from '@components/data/IngestionCatalog/IngestionCatalogCard';
import Breadcrumbs from '../../../components/Breadcrumbs';
import { useFormatter } from '../../../components/i18n';
import useConnectedDocumentModifier from '../../../utils/hooks/useConnectedDocumentModifier';
import PageContainer from '../../../components/PageContainer';
import Loader, { LoaderVariant } from '../../../components/Loader';
import useQueryLoading from '../../../utils/hooks/useQueryLoading';
import ListCardsContent from '../../../components/list_cards/ListCardsContent';
import { MESSAGING$ } from '../../../relay/environment';

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

type IngestionCatalogParsed = {
  contracts: IngestionConnector[];
  description: string;
  entity_type: string;
  id: string;
  name: string;
};

type IngestionTypeMap = {
  string: string;
  number: number;
  boolean: boolean;
};

export type IngestionTypedProperty<K extends keyof IngestionTypeMap = keyof IngestionTypeMap> = {
  type: K;
  default: IngestionTypeMap[K];
  description: string;
};

export interface IngestionConnector {
  title: string,
  slug: string,
  description: string,
  short_description: string,
  logo: string,
  use_cases: string[],
  verified: boolean,
  last_verified_date: string,
  playbook_supported: boolean,
  max_confidence_level: number,
  support_version: string,
  subscription_link: string,
  source_code: string,
  manager_supported: boolean,
  container_version: string,
  container_image: string,
  container_type: IngestionConnectorType,
  config_schema: {
    $schema: string,
    $id: string,
    type: string,
    properties: {
      [key: string]: IngestionTypedProperty
    },
    required: string[],
    additionalProperties: boolean,
  }
}

const IngestionCatalogComponent = ({
  queryRef,
}: IngestionCatalogComponentProps) => {
  const { t_i18n } = useFormatter();
  const { setTitle } = useConnectedDocumentModifier();
  setTitle(t_i18n('Catalog | Ingestion | Data'));
  const [catalogsParsed, setCatalogsParsed] = useState<IngestionCatalogParsed[]>([]);

  const { catalogs } = usePreloadedQuery(
    ingestionCatalogQuery,
    queryRef,
  );

  useEffect(() => {
    catalogs.forEach((catalog) => {
      const finalContracts: IngestionConnector[] = [];
      catalog.contracts.forEach((contract) => {
        try {
          const parsedContract = JSON.parse(contract);
          if (parsedContract.manager_supported) finalContracts.push(parsedContract);
        } catch (e) {
          MESSAGING$.notifyError(t_i18n('Failed to parse a contract'));
        }
        const finalCatalog = { ...catalog, contracts: finalContracts };
        setCatalogsParsed([...catalogsParsed, finalCatalog]);
      });
    });
  }, [catalogs]);

  return (
    <>
      <IngestionMenu />
      <PageContainer withRightMenu withGap>
        <Breadcrumbs elements={[{ label: t_i18n('Data') }, { label: t_i18n('Ingestion') }, { label: t_i18n('Catalog'), current: true }]} />
        {catalogsParsed.map((catalog) => {
          return catalog.contracts.length > 0 && (
            <ListCardsContent
              key={catalog.id}
              hasMore={() => false}
              isLoading={() => false}
              dataList={catalog.contracts}
              dataListId={catalog.id}
              globalCount={catalog.contracts.length}
              CardComponent={IngestionCatalogCard}
              rowHeight={350}
            />
          );
        })}
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
