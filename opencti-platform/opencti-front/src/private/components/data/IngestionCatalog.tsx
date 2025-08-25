import React, { Suspense, useEffect, useState } from 'react';
import IngestionMenu from '@components/data/IngestionMenu';
import { graphql, PreloadedQuery, usePreloadedQuery } from 'react-relay';
import { IngestionCatalogQuery } from '@components/data/__generated__/IngestionCatalogQuery.graphql';
import IngestionCatalogCard, { IngestionConnectorType } from '@components/data/IngestionCatalog/IngestionCatalogCard';
import EnterpriseEdition from '@components/common/entreprise_edition/EnterpriseEdition';
import Breadcrumbs from '../../../components/Breadcrumbs';
import { useFormatter } from '../../../components/i18n';
import useConnectedDocumentModifier from '../../../utils/hooks/useConnectedDocumentModifier';
import PageContainer from '../../../components/PageContainer';
import Loader, { LoaderVariant } from '../../../components/Loader';
import useQueryLoading from '../../../utils/hooks/useQueryLoading';
import ListCardsContent from '../../../components/list_cards/ListCardsContent';
import { MESSAGING$ } from '../../../relay/environment';
import GradientButton from '../../../components/GradientButton';
import SearchInput from '../../../components/SearchInput';
import useEnterpriseEdition from '../../../utils/hooks/useEnterpriseEdition';

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

type IngestionTypeMap = {
  string: string;
  integer: number;
  dict: object;
  array: string[];
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
  const isEnterpriseEdition = useEnterpriseEdition();
  const { t_i18n } = useFormatter();
  const { setTitle } = useConnectedDocumentModifier();
  setTitle(t_i18n('Connector catalog | Ingestion | Data'));
  const [catalogsParsed, setCatalogsParsed] = useState<IngestionCatalogParsed[]>([]);

  const { catalogs } = usePreloadedQuery(
    ingestionCatalogQuery,
    queryRef,
  );

  const { filteredCatalogs, filters, setFilters } = useIngestionCatalogFilters({
    catalogs,
    searchParams,
  });

  const allContracts: IngestionConnector[] = [];

  for (const catalog of catalogs) {
    for (const contract of catalog.contracts) {
      try {
        const parsedContract = JSON.parse(contract);
        if (parsedContract.manager_supported) {
          allContracts.push(parsedContract);
        }
      } catch (e) {
        // let this comment to avoid empty block ts error
      }
    }
  }

  return (
    <>
      <IngestionMenu />
      <PageContainer withRightMenu withGap>
        <Breadcrumbs elements={[{ label: t_i18n('Data') }, { label: t_i18n('Ingestion') }, { label: t_i18n('Connector catalog'), current: true }]} />

        {!isEnterpriseEdition && <EnterpriseEdition />}

        <Stack flexDirection="row">
          <IngestionCatalogFilters
            contracts={allContracts}
            filters={filters}
            onFiltersChange={setFilters}
          />

        <div style={{ display: 'flex', justifyContent: 'space-between' }}>
          <SearchInput disabled />
          <GradientButton
            size="small"
            sx={{ marginLeft: 1 }}
            href={'https://filigran.notion.site/OpenCTI-Ecosystem-868329e9fb734fca89692b2ed6087e76'}
            target="_blank"
            title={t_i18n('Browse more')}
          >
            {t_i18n('Browse more').toUpperCase()}
          </GradientButton>
        </Stack>

        {filteredCatalogs.map((catalog) => (
          <ListCardsContent
            key={catalog.id}
            hasMore={() => false}
            isLoading={() => false}
            dataList={catalog.contracts}
            dataListId={catalog.id}
            globalCount={catalog.contracts.length}
            CardComponent={(props: React.ComponentProps<typeof IngestionCatalogCard>) => (
              <IngestionCatalogCard
                {...props}
                isEnterpriseEdition={isEnterpriseEdition}
              />
            )}
            rowHeight={350}
          />
        ))}
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
