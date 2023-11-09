import fileDownload from 'js-file-download';
import pjson from '../../../../package.json';

interface workspaceToExport {
  name: string
  type?: string
  manifest?: string
}

const handleExportJson = (workspace: workspaceToExport) => {
  const dashboardName = workspace.name;
  const dashboardConfig = JSON.stringify({
    openCTI_version: pjson.version,
    type: workspace.type,
    configuration: {
      name: dashboardName,
      manifest: workspace.manifest,
    },
  }, null, 2);
  const blob = new Blob([dashboardConfig], { type: 'text/json' });
  const [day, month, year] = new Date().toLocaleDateString('fr-FR').split('/');
  const fileName = `${year}${month}${day}_octi_dashboard_${dashboardName}`;

  fileDownload(blob, fileName, 'application/json');
};

export default handleExportJson;
