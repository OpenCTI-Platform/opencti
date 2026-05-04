import { BaseSyntheticEvent, useRef } from 'react';
import fileDownload from 'js-file-download';
import VisuallyHiddenInput from '../../private/components/common/VisuallyHiddenInput';
import { DashboardLike } from './dashboard-types';

interface useDashboardImportExportProps {
  onExport: (entityId: string) => Promise<string | null>;
  configType: string;
  entity: Pick<DashboardLike, 'id' | 'name'>;
}

export const useDashboardExport = ({
  onExport,
  configType,
  entity,
}: useDashboardImportExportProps) => {
  const handleExport = () => {
    onExport(entity.id)
      .then((exportedDashboard: string | null) => {
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
      });
  };
  return { handleExport };
};

export const useDashboardImport = ({ onImport }: {
  onImport: (file: File) => Promise<void>;
}) => {
  const inputRef = useRef<HTMLInputElement | null>(null);

  const _onChange = (event: BaseSyntheticEvent) => {
    const importedFile = event.target.files[0];
    onImport(importedFile).finally(() => {
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
