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
      name
      theme_background
      theme_paper
      theme_nav
      theme_primary
      theme_secondary
      theme_accent
      theme_text_color
      theme_logo
      theme_logo_collapsed
      theme_logo_login      
    }
  }
`;

const handleExportJson = async (theme: themeToExport) => {
  const data = await fetchQuery(ThemeExportHandlerQuery, { id: theme.id }).toPromise();
  const result = data as ThemeExportHandlerQuery$data;

  if (!result.theme) return;

  const themeData = { ...result.theme };

  const jsonString = JSON.stringify(themeData, null, 2);
  const blob = new Blob([jsonString], { type: 'application/json' });
  const todayDate = new Date().toISOString().split('T')[0].replaceAll('-', '');
  const fileName = `${todayDate}_octi_theme_${theme.name.toLowerCase()}.json`;
  fileDownload(blob, fileName);
};

export default handleExportJson;
