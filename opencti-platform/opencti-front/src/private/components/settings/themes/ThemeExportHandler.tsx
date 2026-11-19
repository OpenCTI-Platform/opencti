import { graphql } from 'relay-runtime';
import fileDownload from 'js-file-download';
import { fetchQuery } from '../../../../relay/environment';
import { ThemeExportHandlerQuery$data } from './__generated__/ThemeExportHandlerQuery.graphql';

interface themeToExport {
  id: string;
  name: string;
}

// The content of the file is built by the backend, in the format of the theme import
const ThemeExportHandlerQuery = graphql`
  query ThemeExportHandlerQuery($id: ID!) {
    theme(id: $id) {
      name
      toConfigurationExport
    }
  }
`;

const handleExportJson = async (theme: themeToExport) => {
  const data = await fetchQuery(ThemeExportHandlerQuery, { id: theme.id }).toPromise();
  const result = data as ThemeExportHandlerQuery$data;

  if (!result.theme) return;

  const blob = new Blob([result.theme.toConfigurationExport], { type: 'application/json' });
  const todayDate = new Date().toISOString().split('T')[0].replaceAll('-', '');
  const fileName = `${todayDate}_octi_theme_${theme.name.toLowerCase()}.json`;
  fileDownload(blob, fileName);
};

export default handleExportJson;
