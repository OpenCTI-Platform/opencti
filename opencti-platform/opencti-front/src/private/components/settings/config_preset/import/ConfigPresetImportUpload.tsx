import React, { FunctionComponent, ReactNode, useMemo } from 'react';
import { graphql } from 'react-relay';
import { useTheme } from '@mui/material/styles';
import { Text } from '@filigran/design-system';
import { useFormatter } from '../../../../../components/i18n';
import type { Theme } from '../../../../../components/Theme';
import useApiMutation from '../../../../../utils/hooks/useApiMutation';
import ConfigPresetBundleFileSelect from './ConfigPresetBundleFileSelect';
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
  // The name of the bundle being read or applied: the field then shows it and is disabled, and what the bundle is doing comes under it
  busyFileName?: string | null;
  // Under the field: the progress of the bundle, or what went wrong with it (the field is then free to pick another file)
  children?: ReactNode;
}

// The name of an uploaded zip, from its path in the storage
export const getConfigPresetImportFileName = (fileId: string) => fileId.slice(fileId.lastIndexOf('/') + 1);

// The zip is uploaded once: the preview and the import only take its id
const ConfigPresetImportUpload: FunctionComponent<ConfigPresetImportUploadProps> = ({ onUploaded, busyFileName, children }) => {
  const { t_i18n } = useFormatter();
  const theme = useTheme<Theme>();
  const [commitUpload, uploading] = useApiMutation<ConfigPresetImportUploadMutation>(configPresetImportUploadMutation);
  // Only the name is shown: the file is on the platform
  const busyFile = useMemo(() => (busyFileName ? new File([], busyFileName, { type: 'application/zip' }) : null), [busyFileName]);
  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: theme.spacing(2) }}>
      <Text variant="content-base">{t_i18n('Select the configuration bundle (zip) exported from another platform.')}</Text>
      {/* The file is uploaded as soon as it is picked, so the field holds no selection, but the one that is read or applied */}
      <ConfigPresetBundleFileSelect
        value={busyFile}
        loading={uploading}
        disabled={uploading || !!busyFile}
        data-testid="config-preset-import-file"
        onFileChange={(file) => {
          if (file) {
            commitUpload({ variables: { file }, onCompleted: onUploaded });
          }
        }}
      />
      {children}
    </div>
  );
};

export default ConfigPresetImportUpload;
