import { graphql } from 'relay-runtime';
import fileDownload from 'js-file-download';
import { fetchQuery } from '../../../../relay/environment';
import { ThemeExportHandlerQuery$data } from './__generated__/ThemeExportHandlerQuery.graphql';

interface themeToExport {
  id: string
  name: string
}

const ThemeExportHandlerQuery = graphql`
  query ThemeExportHandlerQuery($id: ID!) {
    theme(id: $id) {
      toConfigurationExport
    }
  }
`;

const handleExportJson = async (theme: themeToExport) => {
  const data = await fetchQuery(ThemeExportHandlerQuery, { id: theme.id }).toPromise();
  const result = data as ThemeExportHandlerQuery$data;

  if (!result.theme) return;

  const blob = new Blob([result.theme.toConfigurationExport], { type: 'text/json' });
  const todayDate = new Date().toISOString().split('T')[0].replaceAll('-', '');
  const fileName = `${todayDate}_octi_theme_${theme.name}.json`;
  fileDownload(blob, fileName);
};

export default handleExportJson;
