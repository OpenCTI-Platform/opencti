import React, { Suspense } from 'react';
import IngestionMenu from '@components/data/IngestionMenu';
import { graphql, PreloadedQuery, usePreloadedQuery } from 'react-relay';
import { IngestionCatalogQuery } from '@components/data/__generated__/IngestionCatalogQuery.graphql';
import IngestionCatalogCard, { IngestionConnectorType } from '@components/data/IngestionCatalog/IngestionCatalogCard';
import useIngestionCatalogFilters from '@components/data/IngestionCatalog/hooks/useIngestionCatalogFilters';
import { useSearchParams } from 'react-router-dom';
import { Stack } from '@mui/material';
import { Search } from '@mui/icons-material';
import Breadcrumbs from '../../../components/Breadcrumbs';
import { useFormatter } from '../../../components/i18n';
import useConnectedDocumentModifier from '../../../utils/hooks/useConnectedDocumentModifier';
import PageContainer from '../../../components/PageContainer';
import Loader, { LoaderVariant } from '../../../components/Loader';
import useQueryLoading from '../../../utils/hooks/useQueryLoading';
import ListCardsContent from '../../../components/list_cards/ListCardsContent';
import GradientButton from '../../../components/GradientButton';
import IngestionCatalogFilters from './IngestionCatalog/IngestionCatalogFilters';
import GradientCard from '../../../components/GradientCard';
import { MESSAGING$ } from '../../../relay/environment';
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

const BrowseMoreButton = () => {
  const { t_i18n } = useFormatter();

  return (
    <GradientButton
      size="small"
      sx={{ marginLeft: 1 }}
      href={'https://filigran.notion.site/OpenCTI-Ecosystem-868329e9fb734fca89692b2ed6087e76'}
      target="_blank"
      title={t_i18n('Browse more')}
    >
      {t_i18n('Browse more').toUpperCase()}
    </GradientButton>
  );
};

const CatalogsEmptyState = () => {
  const { t_i18n } = useFormatter();
  return (
    <Stack
      justifyContent="center"
      alignItems="center"
      sx={{
        minHeight: '50vh',
      }}
    >
      <GradientCard sx={{
        px: 10,
        display: 'flex',
        flexDirection: 'column',
        alignItems: 'center',
        gap: 4,
      }}
      >
        <Stack flexDirection="row" alignItems="flex-start" gap={1}>
          <GradientCard.Icon icon={Search} size="large" />

          <Stack>
            <GradientCard.Text sx={{ whiteSpace: 'pre' }}>{t_i18n('Sorry, we couldn\'t find any results for your search.')}</GradientCard.Text>
            <GradientCard.Text sx={{ whiteSpace: 'pre' }}>{t_i18n('For more results, you can search in the XTM Hub.')}</GradientCard.Text>
          </Stack>
        </Stack>

        <BrowseMoreButton />
      </GradientCard>
    </Stack>
  );
};

const IngestionCatalogComponent = ({
  queryRef,
}: IngestionCatalogComponentProps) => {
  const isEnterpriseEdition = useEnterpriseEdition();
  const { t_i18n } = useFormatter();
  const { setTitle } = useConnectedDocumentModifier();
  const [searchParams] = useSearchParams();

  setTitle(t_i18n('Connector catalog | Ingestion | Data'));

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
        allContracts.push(parsedContract);
      } catch (e) {
        MESSAGING$.notifyError(t_i18n('Failed to parse a contract'));
      }
    }
  }

  return (
    <>
      <IngestionMenu />
      <PageContainer withRightMenu withGap>
        <Breadcrumbs elements={[{ label: t_i18n('Data') }, { label: t_i18n('Ingestion') }, { label: t_i18n('Connector catalog'), current: true }]} />

        <Stack flexDirection="row">
          <IngestionCatalogFilters
            contracts={allContracts}
            filters={filters}
            onFiltersChange={setFilters}
          />

          <BrowseMoreButton />
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

        {filteredCatalogs.length === 0 && (
          <CatalogsEmptyState />
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
