import React, { FunctionComponent } from 'react';
import { type FileRejection, FileSelect } from '@filigran/design-system';
import { useFormatter } from '../../../../../components/i18n';

// The same limit as the backend (CONFIG_PRESET_IMPORT_MAX_ZIP_SIZE in configPreset-import-bundle.ts), which refuses a larger zip:
// the field says so before the upload. Change both together.
export const CONFIG_PRESET_MAX_ZIP_SIZE = 50 * 1024 * 1024;

// What a file field says of a file it refuses: not in the format it accepts, or too large
export const useFileRejectionMessage = () => {
  const { t_i18n } = useFormatter();
  return (rejections: FileRejection[]) => (
    rejections[0].reason === 'accept' ? t_i18n('This file is not in the specified format') : t_i18n('This file is too large')
  );
};

interface ConfigPresetBundleFileSelectProps {
  value: File | null;
  loading?: boolean;
  disabled?: boolean;
  // The file picked, null when the field is cleared
  onFileChange: (file: File | null) => void;
  'data-testid'?: string;
}

// The field of a configuration bundle (zip), the same wherever a bundle is uploaded: the import wizard and the partial import
const ConfigPresetBundleFileSelect: FunctionComponent<ConfigPresetBundleFileSelectProps> = ({ value, loading, disabled, onFileChange, 'data-testid': testId }) => {
  const { t_i18n } = useFormatter();
  const rejectionMessage = useFileRejectionMessage();
  return (
    <FileSelect
      value={value}
      triggerLabel={t_i18n('Upload a configuration bundle')}
      placeholder={t_i18n('No file selected.')}
      accept=".zip,application/zip"
      maxSize={CONFIG_PRESET_MAX_ZIP_SIZE}
      rejectionMessage={rejectionMessage}
      loading={loading}
      disabled={disabled}
      data-testid={testId}
      onValueChange={(file) => onFileChange(file instanceof File ? file : null)}
    />
  );
};

export default ConfigPresetBundleFileSelect;
