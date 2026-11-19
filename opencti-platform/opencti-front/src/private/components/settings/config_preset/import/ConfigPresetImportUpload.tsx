import React, { FunctionComponent } from 'react';
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
}

// The zip is uploaded once: the preview and the import only take its id
const ConfigPresetImportUpload: FunctionComponent<ConfigPresetImportUploadProps> = ({ onUploaded }) => {
  const { t_i18n } = useFormatter();
  const theme = useTheme<Theme>();
  const [commitUpload, uploading] = useApiMutation<ConfigPresetImportUploadMutation>(configPresetImportUploadMutation);
  return (
    <div style={{ display: 'flex', flexDirection: 'column', alignItems: 'flex-start', gap: theme.spacing(2) }}>
      <Text variant="content-base">{t_i18n('Select the configuration bundle (zip) exported from another platform.')}</Text>
      {/* The file is uploaded as soon as it is picked, so the field never holds a selection */}
      <ConfigPresetBundleFileSelect
        value={null}
        loading={uploading}
        disabled={uploading}
        data-testid="config-preset-import-file"
        onFileChange={(file) => {
          if (file) {
            commitUpload({ variables: { file }, onCompleted: onUploaded });
          }
        }}
      />
    </div>
  );
};

export default ConfigPresetImportUpload;
