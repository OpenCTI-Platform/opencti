import fileDownload from 'js-file-download';
import type { ExportableDashboardLike } from '../dashboard-types';
import { MESSAGING$ } from '../../../relay/environment';

interface getDashboardImportExportHandlerParams {
  onExport: (entityId: string) => Promise<string | null>;
  configType: string;
  entity: ExportableDashboardLike;
}

export const getDashboardExportHandler = ({
  onExport,
  configType,
  entity,
}: getDashboardImportExportHandlerParams) => {
  return async () => {
    try {
      const exportedDashboard = await onExport(entity.id);
      if (!exportedDashboard) {
        return;
      }
      const blob = new Blob([exportedDashboard], {
        type: 'text/json',
      });
      const [day, month, year] = new Date()
        .toLocaleDateString('fr-FR')
        .split('/');
      const fileName = `${year}${month}${day}_octi_${configType}_${entity.name}.json`;
      fileDownload(blob, fileName);
    } catch (error) {
      MESSAGING$.notifyCustomRelayError(error, {
        name: 'An unknown error has occurred! Please try again later.',
      });
    }
  };
};
