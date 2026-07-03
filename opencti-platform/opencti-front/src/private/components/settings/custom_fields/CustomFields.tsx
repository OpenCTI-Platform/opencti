import React from 'react';
import { graphql } from 'react-relay';
import Chip from '@mui/material/Chip';
import ExtensionOutlined from '@mui/icons-material/ExtensionOutlined';
import CustomFieldCreation from './CustomFieldCreation';
import CustomFieldPopover from './CustomFieldPopover';
import { usePaginationLocalStorage } from '../../../../utils/hooks/useLocalStorage';
import useQueryLoading from '../../../../utils/hooks/useQueryLoading';
import { CustomFieldsLinesPaginationQuery, CustomFieldsLinesPaginationQuery$variables } from './__generated__/CustomFieldsLinesPaginationQuery.graphql';
import { CustomFieldsLine_node$data } from './__generated__/CustomFieldsLine_node.graphql';
import { useFormatter } from '../../../../components/i18n';
import Breadcrumbs from '../../../../components/Breadcrumbs';
import useConnectedDocumentModifier from '../../../../utils/hooks/useConnectedDocumentModifier';
import { emptyFilterGroup, useBuildEntityTypeBasedFilterContext } from '../../../../utils/filters/filtersUtils';
import { DataTableProps } from '../../../../components/dataGrid/dataTableTypes';
import { UsePreloadedPaginationFragment } from '../../../../utils/hooks/usePreloadedPaginationFragment';
import DataTable from '../../../../components/dataGrid/DataTable';
import FieldOrEmpty from '../../../../components/FieldOrEmpty';
import { defaultRender } from '../../../../components/dataGrid/dataTableUtils';
import TagsOverflow from '../../../../components/common/tag/TagsOverflow';

export const customFieldsQuery = graphql`
  query CustomFieldsLinesPaginationQuery(
    $search: String
    $count: Int!
    $cursor: ID
    $orderBy: CustomFieldDefinitionsOrdering
    $orderMode: OrderingMode
  ) {
    ...CustomFieldsLines_data
    @arguments(
      search: $search
      count: $count
      cursor: $cursor
      orderBy: $orderBy
      orderMode: $orderMode
    )
  }
`;

export const customFieldsFragment = graphql`
  fragment CustomFieldsLines_data on Query
  @argumentDefinitions(
    search: { type: "String" }
    count: { type: "Int", defaultValue: 25 }
    cursor: { type: "ID" }
    orderBy: { type: "CustomFieldDefinitionsOrdering", defaultValue: label }
    orderMode: { type: "OrderingMode", defaultValue: asc }
  )
  @refetchable(queryName: "CustomFieldsLinesRefetchQuery") {
    customFieldDefinitions(
      search: $search
      first: $count
      after: $cursor
      orderBy: $orderBy
      orderMode: $orderMode
    ) @connection(key: "Pagination_customFieldDefinitions") {
      edges {
        node {
          ...CustomFieldsLine_node
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

export const CustomFieldsLineFragment = graphql`
  fragment CustomFieldsLine_node on CustomFieldDefinition {
    id
    name
    label
    field_type
    mandatory
    default_value
    entity_types
  }
`;

const LOCAL_STORAGE_KEY = 'custom-fields';

const CustomFields = () => {
  const { t_i18n } = useFormatter();
  const { setTitle } = useConnectedDocumentModifier();
  setTitle(t_i18n('Custom Fields | Taxonomies | Settings'));

  const initialValues = {
    searchTerm: '',
    sortBy: 'label',
    orderAsc: true,
    filters: emptyFilterGroup,
  };

  const {
    viewStorage,
    helpers,
    paginationOptions,
  } = usePaginationLocalStorage<CustomFieldsLinesPaginationQuery$variables>(
    LOCAL_STORAGE_KEY,
    initialValues,
  );

  const { filters } = viewStorage;
  const contextFilters = useBuildEntityTypeBasedFilterContext('CustomFieldDefinition', filters);

  const queryPaginationOptions = {
    ...paginationOptions,
    filters: contextFilters,
  } as unknown as CustomFieldsLinesPaginationQuery$variables;

  const queryRef = useQueryLoading<CustomFieldsLinesPaginationQuery>(
    customFieldsQuery,
    queryPaginationOptions,
  );

  const dataColumns: DataTableProps['dataColumns'] = {
    label: {
      id: 'label',
      label: 'Label',
      percentWidth: 15,
      render: (data: CustomFieldsLine_node$data) => defaultRender(data.label),
    },
    mandatory: {
      id: 'mandatory',
      label: 'Mandatory',
      percentWidth: 8,
      isSortable: false,
      render: (data: CustomFieldsLine_node$data) => (data.mandatory ? t_i18n('Yes') : t_i18n('No')),
    },
    default_value: {
      id: 'default_value',
      label: 'Default value',
      percentWidth: 15,
      isSortable: false,
      render: (data: CustomFieldsLine_node$data) => (
        <FieldOrEmpty source={data.default_value}>
          {data.default_value}
        </FieldOrEmpty>
      ),
    },
    entity_types: {
      id: 'entity_types',
      label: 'Used in',
      percentWidth: 30,
      isSortable: false,
      render: (data: CustomFieldsLine_node$data) => (
        <FieldOrEmpty source={data.entity_types}>
          <TagsOverflow
            items={data.entity_types ?? []}
            getKey={(entityType) => entityType}
            getLabel={(entityType) => t_i18n(`entity_${entityType}`)}
            renderTag={(entityType) => (
              <Chip key={entityType} label={t_i18n(`entity_${entityType}`)} style={{ marginRight: 5 }} />
            )}
          />
        </FieldOrEmpty>
      ),
    },
    field_type: {
      id: 'field_type',
      label: 'Type',
      percentWidth: 12,
      render: (data: CustomFieldsLine_node$data) => defaultRender(data.field_type),
    },
    name: {
      id: 'name',
      label: 'Technical name',
      percentWidth: 20,
    },
  };

  const preloadedPaginationProps = {
    linesQuery: customFieldsQuery,
    linesFragment: customFieldsFragment,
    queryRef,
    nodePath: ['customFieldDefinitions', 'pageInfo', 'globalCount'],
    setNumberOfElements: helpers.handleSetNumberOfElements,
  } as UsePreloadedPaginationFragment<CustomFieldsLinesPaginationQuery>;

  return (
    <div style={{ marginRight: 200 }} data-testid="custom-fields-page">
      <Breadcrumbs elements={[{ label: t_i18n('Settings') }, { label: t_i18n('Taxonomies') }, { label: t_i18n('Custom fields'), current: true }]} />
      {queryRef && (
        <DataTable
          dataColumns={dataColumns}
          resolvePath={(data) => data.customFieldDefinitions?.edges?.map(({ node }: { node: CustomFieldsLine_node$data }) => node)}
          storageKey={LOCAL_STORAGE_KEY}
          initialValues={initialValues}
          contextFilters={contextFilters}
          lineFragment={CustomFieldsLineFragment}
          disableNavigation
          disableLineSelection
          preloadedPaginationProps={preloadedPaginationProps}
          actions={(row) => <CustomFieldPopover data={row} paginationOptions={paginationOptions} />}
          searchContextFinal={{ entityTypes: ['CustomFieldDefinition'] }}
          icon={() => <ExtensionOutlined />}
          createButton={<CustomFieldCreation paginationOptions={paginationOptions} />}
        />
      )}
    </div>
  );
};

export default CustomFields;
