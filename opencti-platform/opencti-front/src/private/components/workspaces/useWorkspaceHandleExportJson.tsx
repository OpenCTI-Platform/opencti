import fileDownload from 'js-file-download';
import { graphql } from 'react-relay';
import { workspaceExportHandlerQuery$data } from '@components/workspaces/__generated__/workspaceExportHandlerQuery.graphql';
import { fetchQuery, MESSAGING$ } from '../../../relay/environment';
import { useFormatter } from 'src/components/i18n';

interface workspaceToExport {
  id: string;
  name: string;
}

const WorkspaceExportHandlerQuery = graphql`
    query workspaceExportHandlerQuery($id: String!) {
        workspace(id: $id) {
            toConfigurationExport
        }
    }
`;

const useWorkspaceHandleExportJson = () => {
  const { t_i18n } = useFormatter();

  const workspaceHandleExportJson = (workspace: workspaceToExport) => {
    fetchQuery(WorkspaceExportHandlerQuery, { id: workspace.id })
      .toPromise()
      .then((data) => {
        const result = data as workspaceExportHandlerQuery$data | null | undefined;
        if (result?.workspace?.toConfigurationExport) {
          const blob = new Blob([result.workspace.toConfigurationExport], { type: 'text/json' });
          const [day, month, year] = new Date().toLocaleDateString('fr-FR').split('/');
          const fileName = `${year}${month}${day}_octi_dashboard_${workspace.name}.json`;
          fileDownload(blob, fileName);
        } else {
          MESSAGING$.notifyError(t_i18n('Failed to export dashboard'));
        }
      })
      .catch((e) => {
        MESSAGING$.notifyRelayError(e);
        return null;
      });
  };

  return { workspaceHandleExportJson };
};

export default useWorkspaceHandleExportJson;
