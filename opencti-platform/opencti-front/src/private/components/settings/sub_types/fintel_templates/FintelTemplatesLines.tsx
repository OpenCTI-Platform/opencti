import { FunctionComponent } from 'react';
import FintelTemplatePopover from './FintelTemplatePopover';
import ItemBoolean from '../../../../../components/ItemBoolean';
import { resolveLink } from '../../../../../utils/Entity';
import { DataTableVariant } from '../../../../../components/dataGrid/dataTableTypes';
import DataTableWithoutFragment from '../../../../../components/dataGrid/DataTableWithoutFragment';
import { useFormatter } from '../../../../../components/i18n';
import { FintelTemplatesManager_templates$data } from './__generated__/FintelTemplatesManager_templates.graphql';
import Tag from '@common/tag/Tag';
import { useTheme } from '@mui/material';
import { EMPTY_VALUE } from 'src/utils/String';
import { usePaginationLocalStorage } from '../../../../../utils/hooks/useLocalStorage';

export type TemplateType = NonNullable<
  FintelTemplatesManager_templates$data['fintelTemplates']
>['edges'][0]['node'];
type TemplateEdges = FintelTemplatesManager_templates$data['fintelTemplates'];

interface FintelTemplatesLinesProps {
  fintelTemplates: TemplateEdges;
  dataTableRef: HTMLDivElement | null;
  onUpdate: (t: TemplateType) => void;
  entitySettingId: string;
  targetType: string;
}

const FintelTemplatesLines: FunctionComponent<FintelTemplatesLinesProps> = ({
  fintelTemplates,
  dataTableRef,
  onUpdate,
  entitySettingId,
  targetType,
}) => {
  const theme = useTheme();
  const { t_i18n } = useFormatter();

  const storageKey = `fintel-templates-${targetType}`;
  const initialValues = { sortBy: 'default', orderAsc: false };
  const { viewStorage, helpers } = usePaginationLocalStorage(storageKey, initialValues);
  const { sortBy = 'default', orderAsc = false } = viewStorage;

  const templates = (fintelTemplates?.edges ?? []).map(({ node }) => node);
  const sortedTemplates = [...templates].sort((a, b) => {
    let result: number;
    if (sortBy === 'name') {
      result = (a.name ?? '').localeCompare(b.name ?? '');
    } else if (sortBy === 'start_date') {
      result = (a.start_date ?? '').localeCompare(b.start_date ?? '');
    } else {
      result = Number(!!a.default) - Number(!!b.default);
    }
    return orderAsc ? result : -result;
  });

  const dataColumns = {
    name: { percentWidth: 35, isSortable: true },
    description: { percentWidth: 35, isSortable: false },
    default: {
      id: 'default',
      label: 'Default',
      percentWidth: 15,
      isSortable: true,
      render: ({ default: isDefault }) =>
        isDefault ? (
          <Tag color={theme.palette.success.main} label={t_i18n('Default')} />
        ) : (
          EMPTY_VALUE
        ),
    },
    start_date: {
      percentWidth: 15,
      isSortable: true,
      label: t_i18n('Published'),
      render: ({ start_date }: { start_date?: string }) => (
        <ItemBoolean status={!!start_date} label={start_date ? t_i18n('Yes') : t_i18n('No')} />
      ),
    },
  };

  const currentDefaultName = templates.find((node) => node.default)?.name;

  return (
    <DataTableWithoutFragment
      dataColumns={dataColumns}
      storageKey={storageKey}
      initialValues={initialValues}
      onSort={helpers.handleSort}
      getComputeLink={(t: TemplateType) => {
        return `${resolveLink(t.entity_type)}/${targetType}/templates/${t.id}`;
      }}
      globalCount={sortedTemplates.length}
      data={sortedTemplates}
      rootRef={dataTableRef ?? undefined}
      variant={DataTableVariant.inline}
      actions={(template: TemplateType) => (
        <FintelTemplatePopover
          onUpdate={() => onUpdate(template)}
          entitySettingId={entitySettingId}
          templateId={template.id}
          isDefault={!!template.default}
          currentDefaultName={template.default ? undefined : currentDefaultName}
        />
      )}
    />
  );
};

export default FintelTemplatesLines;
