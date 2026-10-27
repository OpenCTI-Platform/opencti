import React, { ChangeEvent, FunctionComponent } from 'react';
import { graphql } from 'react-relay';
import { FileUploadOutlined } from '@mui/icons-material';
import { useTheme } from '@mui/material/styles';
import { Text } from '@filigran/design-system';
import Button from '@common/button/Button';
import { useFormatter } from '../../../../components/i18n';
import type { Theme } from '../../../../components/Theme';
import useApiMutation from '../../../../utils/hooks/useApiMutation';
import VisuallyHiddenInput from '../../common/VisuallyHiddenInput';
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
  const handleChange = (event: ChangeEvent<HTMLInputElement>) => {
    const file = event.target.files?.[0];
    if (file) {
      commitUpload({ variables: { file }, onCompleted: onUploaded });
    }
  };
  return (
    <div style={{ display: 'flex', flexDirection: 'column', alignItems: 'flex-start', gap: theme.spacing(2) }}>
      <Text variant="content-base">{t_i18n('Select the configuration bundle (zip) exported from another platform.')}</Text>
      <Button component="label" startIcon={<FileUploadOutlined />} loading={uploading} disabled={uploading}>
        {t_i18n('Upload a configuration bundle')}
        <VisuallyHiddenInput type="file" accept=".zip,application/zip" data-testid="config-preset-import-file" onChange={handleChange} />
      </Button>
    </div>
  );
};

export default ConfigPresetImportUpload;
