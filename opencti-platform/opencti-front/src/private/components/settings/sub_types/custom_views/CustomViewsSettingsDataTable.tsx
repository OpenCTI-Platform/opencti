import DataTableWithoutFragment from '../../../../../components/dataGrid/DataTableWithoutFragment';
import { DataTableVariant } from '../../../../../components/dataGrid/dataTableTypes';
import { useDataTableLocalSort } from '../../../../../components/dataGrid/dataTableHooks';
import { useFormatter } from '../../../../../components/i18n';
import type { CustomViewsSettings_customViews$data } from './__generated__/CustomViewsSettings_customViews.graphql';
import DrawOutlinedIcon from '@mui/icons-material/DrawOutlined';

type CustomViewsSettingsEntry = CustomViewsSettings_customViews$data['customViews'][number];

interface CustomViewsSettingsDataTableProps {
  customViews: Readonly<CustomViewsSettingsEntry[]>;
  targetType: string;
}

const DATA_COLUMNS = {
  name: { percentWidth: 40, isSortable: true },
  description: { percentWidth: 60, isSortable: false },
} as const;

const DEFAULT_SORT_CONFIG = {
  sortBy: 'name',
  orderAsc: true,
} as const;

const CustomViewsSettingsDataTable = ({
  customViews,
  targetType,
}: CustomViewsSettingsDataTableProps) => {
  const { t_i18n } = useFormatter();
  const getCustomViewLink = (entry: CustomViewsSettingsEntry) => `custom-views/${entry.id}`;
  const storageKey = `custom-views-${targetType}`;
  const { sortedData: sortedCustomViews } = useDataTableLocalSort({
    data: customViews,
    storageKey,
    initialValues: DEFAULT_SORT_CONFIG,
  });

  return (
    <DataTableWithoutFragment
      icon={() => <DrawOutlinedIcon color="secondary" />}
      initialValues={DEFAULT_SORT_CONFIG}
      dataColumns={DATA_COLUMNS}
      storageKey={storageKey}
      globalCount={sortedCustomViews.length}
      data={sortedCustomViews}
      variant={DataTableVariant.inline}
      getComputeLink={getCustomViewLink}
      emptyStateMessage={t_i18n('No entries yet')}
    />
  );
};

export default CustomViewsSettingsDataTable;
