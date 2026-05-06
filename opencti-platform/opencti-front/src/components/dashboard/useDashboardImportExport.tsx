import { BaseSyntheticEvent, useRef } from 'react';
import fileDownload from 'js-file-download';
import VisuallyHiddenInput from '../../private/components/common/VisuallyHiddenInput';
import type { ExportableDashboardLike } from './dashboard-types';
import { MESSAGING$ } from '../../relay/environment';

interface useDashboardImportExportProps {
  onExport: (entityId: string) => Promise<string | null>;
  configType: string;
  entity: ExportableDashboardLike;
}

export const useDashboardExport = ({
  onExport,
  configType,
  entity,
}: useDashboardImportExportProps) => {
  const handleExport = async () => {
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
  return { handleExport };
};

export const useDashboardImport = ({ onImport }: {
  onImport: (file: File) => Promise<void>;
}) => {
  const inputRef = useRef<HTMLInputElement | null>(null);

  const _onChange = (event: BaseSyntheticEvent) => {
    const importedFile = event.target.files[0];
    onImport(importedFile)
      .catch((error) => {
        MESSAGING$.notifyCustomRelayError(error, {
          name: 'An unknown error has occurred! Please try again later.',
        });
      })
      .finally(() => {
        if (inputRef.current) {
          inputRef.current.value = '';
        }
      });
  };

  const handleImport = () => inputRef.current?.click();
  return { _onChange, handleImport, _inputRef: inputRef };
};

export const DashboardHiddenImportInput = ({ helpers }: { helpers: ReturnType<typeof useDashboardImport> }) => {
  return <VisuallyHiddenInput type="file" accept="application/JSON" ref={helpers._inputRef} onChange={helpers._onChange} />;
};
