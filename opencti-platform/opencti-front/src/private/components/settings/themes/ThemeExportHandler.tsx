import { graphql } from 'relay-runtime';
import fileDownload from 'js-file-download';
import { fetchQuery } from '../../../../relay/environment';
import { ThemeExportHandlerQuery$data } from './__generated__/ThemeExportHandlerQuery.graphql';

interface themeToExport {
  id: string
  name: string
}

const ThemeExportHandlerQuery = graphql`
  query ThemeExportHandlerQuery($id: String!) {
    theme(id: $id) {
      toConfigurationExport
    }
  }
`;

const handleExportJson = (theme: themeToExport) => {
  fetchQuery(ThemeExportHandlerQuery, { id: theme.id })
    .toPromise()
    .then((data) => {
      const result = data as ThemeExportHandlerQuery$data;
      if (result.theme) {
        const blob = new Blob([result.theme.toConfigurationExport], { type: 'text/json' });
        const todayDate = new Date().toISOString().split('T')[0].replaceAll('-', '');
        const fileName = `${todayDate}_octi_theme_${theme.name}.json`;
        fileDownload(blob, fileName);
      }
    });
};

export default handleExportJson;
