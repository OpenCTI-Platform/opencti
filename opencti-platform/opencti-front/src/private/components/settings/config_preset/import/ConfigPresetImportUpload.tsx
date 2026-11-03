import React, { FunctionComponent } from 'react';
import { graphql } from 'react-relay';
import { useTheme } from '@mui/material/styles';
import { type FileRejection, FileSelect, Text } from '@filigran/design-system';
import { useFormatter } from '../../../../../components/i18n';
import type { Theme } from '../../../../../components/Theme';
import useApiMutation from '../../../../../utils/hooks/useApiMutation';
import { ConfigPresetImportUploadMutation } from './__generated__/ConfigPresetImportUploadMutation.graphql';

const configPresetImportUploadMutation = graphql`
  mutation ConfigPresetImportUploadMutation($file: Upload!) {
    configPresetImportUpload(file: $file) {
      id
    }
  }
`;

interface ConfigPresetImportUploadProps {
  onUploaded: () => void;
}

// The same limit as the backend, which refuses a larger zip: the field says so before the upload
const MAX_ZIP_SIZE = 50 * 1024 * 1024;

// The zip is uploaded once: the preview and the import only take its id
const ConfigPresetImportUpload: FunctionComponent<ConfigPresetImportUploadProps> = ({ onUploaded }) => {
  const { t_i18n } = useFormatter();
  const theme = useTheme<Theme>();
  const [commitUpload, uploading] = useApiMutation<ConfigPresetImportUploadMutation>(configPresetImportUploadMutation);
  const rejectionMessage = (rejections: FileRejection[]) => (
    rejections[0].reason === 'accept' ? t_i18n('This file is not in the specified format') : t_i18n('This file is too large')
  );
  return (
    <div style={{ display: 'flex', flexDirection: 'column', alignItems: 'flex-start', gap: theme.spacing(2) }}>
      <Text variant="content-base">{t_i18n('Select the configuration bundle (zip) exported from another platform.')}</Text>
      {/* The file is uploaded as soon as it is picked, so the field never holds a selection */}
      <FileSelect
        value={null}
        triggerLabel={t_i18n('Upload a configuration bundle')}
        placeholder={t_i18n('No file selected.')}
        accept=".zip,application/zip"
        maxSize={MAX_ZIP_SIZE}
        rejectionMessage={rejectionMessage}
        loading={uploading}
        disabled={uploading}
        data-testid="config-preset-import-file"
        onValueChange={(value) => {
          if (value instanceof File) {
            commitUpload({ variables: { file: value }, onCompleted: onUploaded });
          }
        }}
      />
    </div>
  );
};

export default ConfigPresetImportUpload;
