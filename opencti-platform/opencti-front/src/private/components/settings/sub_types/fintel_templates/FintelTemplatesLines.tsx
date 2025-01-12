import React, { FunctionComponent } from 'react';
import FintelTemplatePopover from './FintelTemplatePopover';
import { FintelTemplatesGrid_templates$data } from './__generated__/FintelTemplatesGrid_templates.graphql';
import ItemBoolean from '../../../../../components/ItemBoolean';
import { resolveLink } from '../../../../../utils/Entity';
import { DataTableVariant } from '../../../../../components/dataGrid/dataTableTypes';
import DataTableWithoutFragment from '../../../../../components/dataGrid/DataTableWithoutFragment';
import { useFormatter } from '../../../../../components/i18n';

export type TemplateType = NonNullable<FintelTemplatesGrid_templates$data['fintelTemplates']>['edges'][0]['node'];
type TemplateEdges = FintelTemplatesGrid_templates$data['fintelTemplates'];

interface FintelTemplatesLinesProps {
  fintelTemplates: TemplateEdges,
  dataTableRef: HTMLDivElement | null,
  onUpdate: (t: TemplateType) => void,
  entitySettingId: string,
  targetType: string,
}

const FintelTemplatesLines: FunctionComponent<FintelTemplatesLinesProps> = ({
  fintelTemplates,
  dataTableRef,
  onUpdate,
  entitySettingId,
  targetType,
}) => {
  const { t_i18n } = useFormatter();
  const dataColumns = {
    name: { percentWidth: 41, isSortable: false },
    description: { percentWidth: 41, isSortable: false },
    start_date: {
      percentWidth: 18,
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

  return (
    <DataTableWithoutFragment
      dataColumns={dataColumns}
      storageKey={`fintel-templates-${targetType}`}
      useComputeLink={(t: TemplateType) => {
        return `${resolveLink(t.entity_type)}/${targetType}/templates/${t.id}`;
      }}
      globalCount={fintelTemplates?.edges.length ?? 0}
      data={(fintelTemplates?.edges ?? []).map((e) => e.node)}
      rootRef={dataTableRef ?? undefined}
      variant={DataTableVariant.inline}
      actions={(template: TemplateType) => (
        <FintelTemplatePopover
          onUpdate={() => onUpdate(template)}
          entitySettingId={entitySettingId}
          templateId={template.id}
        />
      )}
    />
  );
};

export default FintelTemplatesLines;
