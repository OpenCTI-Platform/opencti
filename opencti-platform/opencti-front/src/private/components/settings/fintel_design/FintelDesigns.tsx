import { graphql } from 'react-relay';
import React, { useState } from 'react';
import {
  FintelDesignsLinesPaginationQuery,
  FintelDesignsLinesPaginationQuery$variables,
} from '@components/settings/fintel_design/__generated__/FintelDesignsLinesPaginationQuery.graphql';
import FintelDesignCreation from '@components/settings/fintel_design/FintelDesignCreation';
import { FintelDesignsLines_data$data } from '@components/settings/fintel_design/__generated__/FintelDesignsLines_data.graphql';
import { FintelDesignsLine_node$data } from '@components/settings/fintel_design/__generated__/FintelDesignsLine_node.graphql';
import EnterpriseEdition from '@components/common/entreprise_edition/EnterpriseEdition';
import { useFormatter } from '../../../../components/i18n';
import { emptyFilterGroup, useBuildEntityTypeBasedFilterContext } from '../../../../utils/filters/filtersUtils';
import { usePaginationLocalStorage } from '../../../../utils/hooks/useLocalStorage';
import useQueryLoading from '../../../../utils/hooks/useQueryLoading';
import { DataTableProps } from '../../../../components/dataGrid/dataTableTypes';
import { UsePreloadedPaginationFragment } from '../../../../utils/hooks/usePreloadedPaginationFragment';
import Breadcrumbs from '../../../../components/Breadcrumbs';
import DataTable from '../../../../components/dataGrid/DataTable';
import ItemIcon from '../../../../components/ItemIcon';
import PageContainer from '../../../../components/PageContainer';
import Alert from '../../../../components/Alert';
import useConnectedDocumentModifier from '../../../../utils/hooks/useConnectedDocumentModifier';
import useEnterpriseEdition from '../../../../utils/hooks/useEnterpriseEdition';
import Tag from '@common/tag/Tag';
import { useTheme } from '@mui/material';
import FintelDesignPopover from '@components/settings/fintel_design/FintelDesignPopover';
import FintelDesignDeletion from '@components/settings/fintel_design/FintelDesignDeletion';
import useGranted, { KNOWLEDGE_KNUPDATE_KNDELETE } from '../../../../utils/hooks/useGranted';

const fintelDesignsQuery = graphql`
  query FintelDesignsLinesPaginationQuery(
    $search: String
    $count: Int!
    $cursor: ID
    $orderBy: FintelDesignOrdering
    $orderMode: OrderingMode
    $filters: FilterGroup
  ) {
    ...FintelDesignsLines_data
    @arguments(
      search: $search
      count: $count
      cursor: $cursor
      orderBy: $orderBy
      orderMode: $orderMode
      filters: $filters
    )
  }
`;

export const fintelDesignsFragment = graphql`
  fragment FintelDesignsLines_data on Query
  @argumentDefinitions(
    search: { type: "String" }
    count: { type: "Int", defaultValue: 25 }
    cursor: { type: "ID" }
    orderBy: { type: "FintelDesignOrdering", defaultValue: name }
    orderMode: { type: "OrderingMode", defaultValue: desc }
    filters: { type: "FilterGroup" }
  ) @refetchable(queryName: "FintelDesignsLinesRefetchQuery") {
    fintelDesigns(
      search: $search
      first: $count
      after: $cursor
      orderBy: $orderBy
      orderMode: $orderMode
      filters: $filters
    ) @connection(key: "Pagination_fintelDesigns") {
      edges {
        node {
          id
          name
          default
          ...FintelDesignsLine_node
        }
      }
      pageInfo {
        endCursor
        hasNextPage
        globalCount
      }
    }
  }
`;

const fintelDesignsLineFragment = graphql`
  fragment FintelDesignsLine_node on FintelDesign {
    id
    name
    file_id
    description
    gradiantFromColor
    gradiantToColor
    textColor
    default
  }
`;

const LOCAL_STORAGE_KEY = 'view-fintel-designs';

type FintelDesignType = NonNullable<
  NonNullable<FintelDesignsLines_data$data['fintelDesigns']>['edges'][number]['node']
>;

type FintelDesignRow = FintelDesignType & {
  name?: string;
  currentDefaultName?: string;
};

const FintelDesigns = () => {
  const isEnterpriseEdition = useEnterpriseEdition();
  const { t_i18n } = useFormatter();
  const theme = useTheme();
  const { setTitle } = useConnectedDocumentModifier();
  const canDelete = useGranted([KNOWLEDGE_KNUPDATE_KNDELETE]);
  setTitle(t_i18n('Fintel design | Customization | Settings'));
  const initialValues = {
    searchTerm: '',
    sortBy: 'name',
    orderAsc: true,
    openExports: false,
    filters: emptyFilterGroup,
  };

  const {
    viewStorage,
    paginationOptions,
    helpers: storageHelpers,
  } = usePaginationLocalStorage<FintelDesignsLinesPaginationQuery$variables>(
    LOCAL_STORAGE_KEY,
    initialValues,
  );

  const { filters } = viewStorage;
  const contextFilters = useBuildEntityTypeBasedFilterContext('FintelDesign', filters);

  const queryPaginationOptions = {
    ...paginationOptions,
    filters: contextFilters,
  } as unknown as FintelDesignsLinesPaginationQuery$variables;

  const queryRef = useQueryLoading<FintelDesignsLinesPaginationQuery>(
    fintelDesignsQuery,
    queryPaginationOptions,
  );
  const [fintelDesignToDelete, setFintelDesignToDelete] = useState<string | null>(null);

  const dataColumns: DataTableProps['dataColumns'] = {
    name: {
      id: 'name',
      label: t_i18n('Name'),
      percentWidth: 30,
      isSortable: true,
    },
    description: {
      id: 'description',
      label: t_i18n('Description'),
      percentWidth: 50,
      isSortable: false,
    },
    default: {
      id: 'default',
      label: t_i18n('Default'),
      percentWidth: 20,
      isSortable: false,
      render: ({ default: isDefault }) => isDefault ? (
        <Tag
          color={theme.palette.success.main}
          labelTextTransform="uppercase"
          label="default"
        />
      ) : '-',
    },
  };

  const preloadedPaginationProps = {
    linesQuery: fintelDesignsQuery,
    linesFragment: fintelDesignsFragment,
    queryRef,
    nodePath: ['fintelDesigns', 'pageInfo', 'globalCount'],
    setNumberOfElements: storageHelpers.handleSetNumberOfElements,
  } as UsePreloadedPaginationFragment<FintelDesignsLinesPaginationQuery>;

  const getRedirectionLink = (fintelDesignId: FintelDesignsLine_node$data) => {
    return `${fintelDesignId.id}`;
  };

  return (
    <div data-testid="fintel-designs-page">
      <PageContainer withGap withRightMenu>
        <Breadcrumbs
          noMargin
          elements={[
            { label: t_i18n('Settings') },
            { label: t_i18n('Customization') },
            { label: t_i18n('Fintel design'), current: true },
          ]}
        />
        {!isEnterpriseEdition ? (
          <EnterpriseEdition feature="Fintel design" />
        ) : (
          <>
            <Alert
              content={t_i18n('If no design configuration is detected, the default settings will be applied.')}
            />
            {queryRef && (
              <DataTable
                dataColumns={dataColumns}
                resolvePath={(data: FintelDesignsLines_data$data) => {
                  const nodes = (data.fintelDesigns?.edges ?? [])
                    .map((n) => n?.node)
                    .filter((node): node is FintelDesignType => Boolean(node));
                  const { defaultDesigns, otherDesigns } = nodes.reduce(
                    (acc, node) => {
                      if (node.default) {
                        acc.defaultDesigns.push(node);
                      } else {
                        acc.otherDesigns.push(node);
                      }
                      return acc;
                    },
                    { defaultDesigns: [] as FintelDesignRow[], otherDesigns: [] as FintelDesignRow[] },
                  );
                  const currentDefaultName = defaultDesigns[0]?.name;
                  return [...defaultDesigns, ...otherDesigns]
                    .map((node) => ({
                      ...node,
                      currentDefaultName: node.default ? undefined : currentDefaultName,
                    }));
                }}
                storageKey={LOCAL_STORAGE_KEY}
                initialValues={initialValues}
                contextFilters={contextFilters}
                getComputeLink={getRedirectionLink}
                lineFragment={fintelDesignsLineFragment}
                disableLineSelection
                preloadedPaginationProps={preloadedPaginationProps}
                createButton={<FintelDesignCreation paginationOptions={queryPaginationOptions} />}
                icon={() => <ItemIcon type="FintelDesign" />}
                actions={(row: FintelDesignRow) => (
                  <FintelDesignPopover
                    fintelDesignId={row.id}
                    isDefault={!!row.default}
                    currentDefaultName={row.currentDefaultName}
                    onDelete={canDelete ? () => setFintelDesignToDelete(row.id) : undefined}
                  />
                )}
              />
            )}
            {fintelDesignToDelete && (
              <FintelDesignDeletion
                id={fintelDesignToDelete}
                isOpen={!!fintelDesignToDelete}
                handleClose={() => setFintelDesignToDelete(null)}
              />
            )}
          </>
        )}
      </PageContainer>
    </div>
  );
};

export default FintelDesigns;
