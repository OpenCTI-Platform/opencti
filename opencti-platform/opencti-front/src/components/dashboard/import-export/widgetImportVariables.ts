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

/**
 * countMissingWidgetVariables on the file being imported. A file that cannot be read (removed or unreadable after its
 * selection) counts nothing: the import goes on, and the server reports the file.
 */
export const countMissingWidgetVariablesInFile = async (file: Pick<Blob, 'text'>, variableIds: ReadonlySet<string>): Promise<number> => {
  try {
    return countMissingWidgetVariables(await file.text(), variableIds);
  } catch {
    return 0;
  }
};
