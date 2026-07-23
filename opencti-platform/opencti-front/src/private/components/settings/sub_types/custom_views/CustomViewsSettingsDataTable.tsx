import { graphql } from 'relay-runtime';
import Insights from '@mui/icons-material/Insights';
import { useTheme } from '@mui/material';
import useQueryLoading from '../../../../../utils/hooks/useQueryLoading';
import DataTable from '../../../../../components/dataGrid/DataTable';
import { DataTableVariant } from '../../../../../components/dataGrid/dataTableTypes';
import { useFormatter } from '../../../../../components/i18n';
import ItemBoolean from '../../../../../components/ItemBoolean';

import type { CustomViewsSettingsDataTablePaginationQuery } from './__generated__/CustomViewsSettingsDataTablePaginationQuery.graphql';
import type { CustomViewsSettingsDataTable_data$data } from './__generated__/CustomViewsSettingsDataTable_data.graphql';
import type { CustomViewsSettingsDataTable_node$data } from './__generated__/CustomViewsSettingsDataTable_node.graphql';
import CustomViewPopover from './CustomViewPopover';
import Tag from '@common/tag/Tag';
import { EMPTY_VALUE } from 'src/utils/String';

interface CustomViewsSettingsDataTableProps {
  targetType: string;
}

const customViewFragment = graphql`
  fragment CustomViewsSettingsDataTable_node on CustomView {
    id
    name
    description
    enabled
    default
    ...CustomViewPopover_customView
  }
`;

export const customViewsLinesQuery = graphql`
  query CustomViewsSettingsDataTablePaginationQuery(
    $count: Int
    $cursor: ID
    $orderBy: CustomViewsOrdering
    $orderMode: OrderingMode
    $entityType: String!
  ) {
    ...CustomViewsSettingsDataTable_data
    @arguments(
      count: $count
      cursor: $cursor
      orderBy: $orderBy
      orderMode: $orderMode
      entityType: $entityType
    )
  }
`;

const customViewsLinesFragment = graphql`
  fragment CustomViewsSettingsDataTable_data on Query
  @argumentDefinitions(
    cursor: { type: "ID" }
    count: { type: "Int" }
    orderBy: { type: "CustomViewsOrdering" }
    orderMode: { type: "OrderingMode" }
    entityType: { type: "String!" }
  ) @refetchable(queryName: "CustomViewsSettingsDataTableRefetchQuery") {
    customViews(
      first: $count
      after: $cursor
      orderBy: $orderBy
      orderMode: $orderMode
      entityType: $entityType
    ) @connection(key: "CustomViewsSettingsDataTable_customViews") {
      edges {
        node {
          id
          ...CustomViewsSettingsDataTable_node
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

const DATA_COLUMNS = {
  name: { percentWidth: 30, isSortable: false },
  description: { percentWidth: 40, isSortable: false },
  customViewDefault: {
    id: 'default',
    label: 'Default',
    percentWidth: 15,
    isSortable: false,
    render: ({ default: isDefault }: CustomViewsSettingsDataTable_node$data) => {
      const DefaultCell = () => {
        const theme = useTheme();
        const { t_i18n } = useFormatter();
        return isDefault ? (
          <Tag color={theme.palette.success.main} label={t_i18n('Default')} />
        ) : EMPTY_VALUE;
      };
      return <DefaultCell />;
    },
  },
  customViewEnabled: {
    id: 'enabled',
    label: 'Status',
    percentWidth: 15,
    isSortable: true,
    render: ({ enabled }: CustomViewsSettingsDataTable_node$data) => {
      const StatusCell = () => {
        const { t_i18n } = useFormatter();
        return (
          <ItemBoolean
            label={enabled ? t_i18n('View is enabled') : t_i18n('View is disabled')}
            status={enabled}
            labelTextTransform="none"
          />
        );
      };
      return <StatusCell />;
    },
  },
} as const;

const resolvePath = (d: CustomViewsSettingsDataTable_data$data) =>
  (d.customViews?.edges ?? []).map((e) => e.node);

const CustomViewsSettingsDataTable = ({
  targetType,
}: CustomViewsSettingsDataTableProps) => {
  const { t_i18n } = useFormatter();
  const getCustomViewLink = (entry: CustomViewsSettingsDataTable_node$data) => {
    return `/dashboard/settings/customization/entity_types/${targetType}/custom-views/${entry.id}`;
  };
  const storageKey = `custom-views-${targetType}`;

  const queryPaginationOptions: CustomViewsSettingsDataTablePaginationQuery['variables'] = {
    entityType: targetType,
    orderBy: 'default',
    orderMode: 'desc',
  };

  const queryRef = useQueryLoading<CustomViewsSettingsDataTablePaginationQuery>(
    customViewsLinesQuery,
    queryPaginationOptions,
  );

  if (!queryRef) {
    return null;
  }

  const preloadedPaginationProps = {
    linesQuery: customViewsLinesQuery,
    linesFragment: customViewsLinesFragment,
    queryRef,
    nodePath: ['customViews', 'pageInfo', 'globalCount'],
  };

  return (
    <DataTable
      initialValues={{ sortBy: 'default', orderAsc: false }}
      dataColumns={DATA_COLUMNS}
      storageKey={storageKey}
      variant={DataTableVariant.inline}
      getComputeLink={getCustomViewLink}
      emptyStateMessage={t_i18n('No entries yet')}
      resolvePath={resolvePath}
      preloadedPaginationProps={preloadedPaginationProps}
      lineFragment={customViewFragment}
      hideSearch={true}
      hideFilters={true}
      disableLineSelection={true}
      actions={(row) => <CustomViewPopover data={row} paginationOptions={queryPaginationOptions} />}
      icon={() => <Insights sx={{ color: 'designSystem.tertiary.blue.500' }} />}
    />
  );
};

export default CustomViewsSettingsDataTable;
