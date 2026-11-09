import { fromB64 } from '../../../utils/String';
import { widgetVariableIds } from '../dashboardVariablesResolution';

/**
 * Number of distinct variables used by an exported widget (the content of the file) that are not in `variableIds`.
 * An export only carries the variable ids, never their names: a count is all that can be told to the user.
 * An unreadable file counts nothing, the import itself reports the error.
 */
export const countMissingWidgetVariables = (fileContent: string, variableIds: ReadonlySet<string>): number => {
  try {
    const { configuration } = JSON.parse(fileContent);
    const widget = JSON.parse(fromB64(configuration));
    return widgetVariableIds(widget).filter((id) => !variableIds.has(id)).length;
  } catch {
    return 0;
  }
};
