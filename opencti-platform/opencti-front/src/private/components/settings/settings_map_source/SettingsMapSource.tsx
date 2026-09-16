import React, { ChangeEvent, FunctionComponent, useState } from 'react';
import { graphql } from 'react-relay';
import Button from '../../../../components/common/button/Button';
import List from '@mui/material/List';
import ListItem from '@mui/material/ListItem';
import ListItemText from '@mui/material/ListItemText';
import Typography from '@mui/material/Typography';
import { CloudUploadOutlined, DeleteOutlined, DownloadOutlined } from '@mui/icons-material';
import Card from '../../../../components/common/card/Card';
import { useFormatter } from '../../../../components/i18n';
import useApiMutation from '../../../../utils/hooks/useApiMutation';
import { APP_BASE_PATH } from '../../../../relay/environment';
import { SettingsQuery$data } from '../__generated__/SettingsQuery.graphql';

const uploadMapCustomFileMutation = graphql`
  mutation SettingsMapSourceUploadMutation($id: ID!, $file: Upload!) {
    settingsEdit(id: $id) {
      uploadMapCustomFile(file: $file) {
        id
        platform_map_custom_file {
          name
          size
        }
      }
    }
  }
`;

const deleteMapCustomFileMutation = graphql`
  mutation SettingsMapSourceDeleteMutation($id: ID!) {
    settingsEdit(id: $id) {
      deleteMapCustomFile {
        id
        platform_map_custom_file {
          name
          size
        }
      }
    }
  }
`;

interface SettingsMapSourceProps {
  settings: SettingsQuery$data['settings'] & { readonly id: string };
}

const SettingsMapSource: FunctionComponent<SettingsMapSourceProps> = ({
  settings,
}) => {
  const { t_i18n, b: formatBytes } = useFormatter();
  const [uploading, setUploading] = useState(false);

  const [commitUpload] = useApiMutation(uploadMapCustomFileMutation);
  const [commitDelete] = useApiMutation(deleteMapCustomFileMutation);

  const customFile = settings.platform_map_custom_file;

  const handleUpload = (event: ChangeEvent<HTMLInputElement>) => {
    const file = event.target.files?.[0];
    event.target.value = '';
    if (!file) return;
    setUploading(true);
    commitUpload({
      variables: { id: settings.id, file },
      onCompleted: () => setUploading(false),
      onError: () => setUploading(false),
    });
  };

  const handleDelete = () => {
    commitDelete({ variables: { id: settings.id } });
  };

  return (
    <Card title={t_i18n('Map configuration')}>
      <List style={{ marginTop: -20 }}>
        <ListItem divider={true}>
          <ListItemText primary={t_i18n('Custom map')} />
          <div>
            <Typography variant="body2" sx={{ marginBottom: 1 }}>
              {customFile
                ? `${customFile.name} (${formatBytes(customFile.size)})`
                : t_i18n('No custom map uploaded, using the bundled map')}
            </Typography>
            <div style={{ display: 'flex', gap: 8 }}>
              {customFile && (
                <Button
                  variant="secondary"
                  size="small"
                  startIcon={<DownloadOutlined />}
                  href={`${APP_BASE_PATH}/maps/world.pmtiles`}
                  download={customFile.name}
                >
                  {t_i18n('Download')}
                </Button>
              )}
              <Button
                component="label"
                variant="secondary"
                size="small"
                startIcon={<CloudUploadOutlined />}
                disabled={uploading}
              >
                {uploading ? t_i18n('Uploading...') : t_i18n('Upload')}
                <input type="file" hidden accept=".pmtiles" onChange={handleUpload} />
              </Button>
              {customFile && (
                <Button
                  variant="secondary"
                  size="small"
                  color="error"
                  startIcon={<DeleteOutlined />}
                  onClick={handleDelete}
                >
                  {t_i18n('Delete')}
                </Button>
              )}
            </div>
          </div>
        </ListItem>
      </List>
    </Card>
  );
};

export default SettingsMapSource;
