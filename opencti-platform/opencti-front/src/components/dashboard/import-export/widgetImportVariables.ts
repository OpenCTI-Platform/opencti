import { fromB64 } from '../../../utils/String';
import { resolveVariablesInFilterGroup } from '../dashboardVariablesResolution';

const TOKEN_SELECTION_KEYS = ['filters', 'dynamicFrom', 'dynamicTo'] as const;

/**
 * Number of distinct variables used by an exported widget (the content of the file) that are not in `variableIds`.
 * An export only carries the variable ids, never their names: a count is all that can be told to the user.
 * An unreadable file counts nothing, the import itself reports the error.
 */
export const countMissingWidgetVariables = (fileContent: string, variableIds: ReadonlySet<string>): number => {
  try {
    const { configuration } = JSON.parse(fileContent);
    const widget = JSON.parse(fromB64(configuration));
    const missing = new Set<string>();
    (widget.dataSelection ?? []).forEach((selection: Record<string, unknown>) => {
      TOKEN_SELECTION_KEYS.forEach((key) => {
        // Resolved against no value: every token of the group is reported as unresolved
        resolveVariablesInFilterGroup(selection[key], new Map()).unresolved
          .filter((id) => !variableIds.has(id))
          .forEach((id) => missing.add(id));
      });
    });
    return missing.size;
  } catch {
    return 0;
  }
};
