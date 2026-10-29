import type { Widget } from '../../utils/widget/widget';
import type { DashboardVariable } from './dashboard-types';
import { resolveVariablesInFilterGroup, toVariableToken } from './dashboardVariablesResolution';
import { getVariableTokenLabel } from './dashboardVariableTokenLabel';

const NO_VALUES = new Map<string, string>();

/**
 * Ids of the variables a widget filters on, once each, in the order they are met. Resolved against no value at all,
 * every token of a filter group is reported unresolved: the resolution already knows how to find them.
 */
export const getWidgetVariableIds = (widget: Pick<Widget, 'dataSelection'>): string[] => {
  const ids = new Set<string>();
  (widget.dataSelection ?? []).forEach(({ filters, dynamicFrom, dynamicTo }) => {
    [filters, dynamicFrom, dynamicTo].forEach((group) => {
      resolveVariablesInFilterGroup(group, NO_VALUES).unresolved.forEach((id) => ids.add(id));
    });
  });
  return [...ids];
};

// Names of the variables a widget filters on; a deleted one, still referenced, reads Deleted variable.
export const getWidgetVariableNames = (
  widget: Pick<Widget, 'dataSelection'>,
  variables: readonly DashboardVariable[],
  t_i18n: (message: string) => string,
): string[] => getWidgetVariableIds(widget).map((id) => (
  getVariableTokenLabel(toVariableToken(id), [...variables], t_i18n)?.label ?? id
));
