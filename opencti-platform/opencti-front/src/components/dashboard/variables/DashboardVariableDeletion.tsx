import { useMemo } from 'react';
import { useFormatter } from '../../i18n';
import { indexedVisualizationTypes, type WidgetVisualizationTypes } from '../../../utils/widget/widgetUtils';
import type { DashboardVariable, DashboardWidget } from '../dashboard-types';
import DashboardVariableDeleteDialog from './DashboardVariableDeleteDialog';
import { useDashboardVariableMutations } from './useDashboardVariableMutations';

export interface DashboardVariableDeletionProps {
  workspaceId: string;
  variable: DashboardVariable;
  usedInWidgetIds: readonly string[];
  // The widgets of the manifest: the ids the server reports but the manifest ignores are dropped.
  widgets: readonly DashboardWidget[];
  onClose: () => void;
}

/**
 * Deletion of a variable: confirmation listing the widgets that will lose their data.
 */
const DashboardVariableDeletion = ({ workspaceId, variable, usedInWidgetIds, widgets, onClose }: DashboardVariableDeletionProps) => {
  const { t_i18n } = useFormatter();
  const { remove } = useDashboardVariableMutations(workspaceId);

  const impactedWidgets = useMemo(() => {
    const used = new Set(usedInWidgetIds);
    return widgets
      .filter(({ id }) => used.has(id))
      .map(({ id, type, parameters }) => {
        const typeName = indexedVisualizationTypes[type as WidgetVisualizationTypes]?.name ?? type;
        return { id, title: parameters?.title || t_i18n(typeName) };
      });
  }, [usedInWidgetIds, widgets, t_i18n]);

  return (
    <DashboardVariableDeleteDialog
      open
      variable={variable}
      widgets={impactedWidgets}
      onConfirm={() => remove(variable.id)}
      onClose={onClose}
    />
  );
};

export default DashboardVariableDeletion;
