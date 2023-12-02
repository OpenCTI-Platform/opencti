import fileDownload from 'js-file-download';
import { graphql } from 'react-relay';
import { workspaceExportHandlerQuery$data } from '@components/workspaces/__generated__/workspaceExportHandlerQuery.graphql';
import { fetchQuery } from '../../../relay/environment';

interface workspaceToExport {
  id: string
  name: string
}

const WorkspaceExportHandlerQuery = graphql`
    query workspaceExportHandlerQuery($id: String!) {
        workspace(id: $id) {
            toConfigurationExport
        }
    }
`;

const handleExportJson = (workspace: workspaceToExport) => {
  fetchQuery(WorkspaceExportHandlerQuery, { id: workspace.id })
    .toPromise()
    .then((data) => {
      const result = data as workspaceExportHandlerQuery$data;
      if (result.workspace) {
        const blob = new Blob([result.workspace.toConfigurationExport], { type: 'text/json' });
        const [day, month, year] = new Date().toLocaleDateString('fr-FR').split('/');
        const fileName = `${year}${month}${day}_octi_dashboard_${workspace.name}`;
        fileDownload(blob, fileName, 'application/json');
      }
    });
};

export default handleExportJson;
