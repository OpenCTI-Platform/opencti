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

export type TemplateType = NonNullable<FintelTemplatesManager_templates$data['fintelTemplates']>['edges'][0]['node'];
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

  const { defaultTemplates, otherTemplates } = (fintelTemplates?.edges ?? []).reduce(
    (acc, { node }) => {
      if (node.default) {
        acc.defaultTemplates.push(node);
      } else {
        acc.otherTemplates.push(node);
      }
      return acc;
    },
    { defaultTemplates: [] as TemplateType[], otherTemplates: [] as TemplateType[] },
  );

  const dataColumns = {
    name: { percentWidth: 35, isSortable: false },
    description: { percentWidth: 35, isSortable: false },
    default: {
      id: 'default',
      label: 'Default',
      percentWidth: 15,
      isSortable: false,
      render: ({ default: isDefault }) => isDefault ? (
        <Tag
          color={theme.palette.success.main}
          label={t_i18n('Default')}
        />
      ) : EMPTY_VALUE,
    },
    start_date: {
      percentWidth: 15,
      isSortable: false,
      label: t_i18n('Published'),
      render: ({ start_date }: { start_date?: string }) => (
        <ItemBoolean
          status={!!start_date}
          label={start_date ? t_i18n('Yes') : t_i18n('No')}
        />
      ),
    },
  };

  const currentDefaultName = defaultTemplates[0]?.name;

  return (
    <DataTableWithoutFragment
      dataColumns={dataColumns}
      storageKey={`fintel-templates-${targetType}`}
      getComputeLink={(t: TemplateType) => {
        return `${resolveLink(t.entity_type)}/${targetType}/templates/${t.id}`;
      }}
      globalCount={fintelTemplates?.edges.length ?? 0}
      data={[...defaultTemplates, ...otherTemplates]}
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
