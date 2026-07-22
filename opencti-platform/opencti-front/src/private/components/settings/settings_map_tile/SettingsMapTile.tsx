import React, { ChangeEvent, FunctionComponent, useState } from 'react';
import { graphql } from 'react-relay';
import Button from '@mui/material/Button';
import List from '@mui/material/List';
import ListItem from '@mui/material/ListItem';
import ListItemText from '@mui/material/ListItemText';
import MenuItem from '@mui/material/MenuItem';
import Select, { SelectChangeEvent } from '@mui/material/Select';
import Typography from '@mui/material/Typography';
import { CloudUploadOutlined, DeleteOutlined } from '@mui/icons-material';
import Card from '../../../../components/common/card/Card';
import { useFormatter } from '../../../../components/i18n';
import useApiMutation from '../../../../utils/hooks/useApiMutation';
import { SettingsQuery$data } from '../__generated__/SettingsQuery.graphql';

const uploadMapTileMutation = graphql`
  mutation SettingsMapTileUploadMutation($id: ID!, $file: Upload!) {
    settingsEdit(id: $id) {
      uploadMapTileData(file: $file) {
        id
        platform_map_tile_server_mode
        platform_map_tile_server_s3_file {
          name
          size
          sha256
        }
      }
    }
  }
`;

const deleteMapTileMutation = graphql`
  mutation SettingsMapTileDeleteMutation($id: ID!) {
    settingsEdit(id: $id) {
      deleteMapTileData {
        id
        platform_map_tile_server_s3_file {
          name
          size
          sha256
        }
      }
    }
  }
`;

interface SettingsMapTileProps {
  settings: SettingsQuery$data['settings'] & { readonly id: string };
  handleSubmitField: (name: string, value: string | boolean) => void;
}

const SettingsMapTile: FunctionComponent<SettingsMapTileProps> = ({
  settings,
  handleSubmitField,
}) => {
  const { t_i18n, b: formatBytes } = useFormatter();
  const [uploading, setUploading] = useState(false);

  const [commitUpload] = useApiMutation(uploadMapTileMutation);
  const [commitDelete] = useApiMutation(deleteMapTileMutation);

  const mode = settings.platform_map_tile_server_mode;
  const s3File = settings.platform_map_tile_server_s3_file;

  const handleModeChange = (event: SelectChangeEvent) => {
    handleSubmitField('platform_map_tile_server_mode', event.target.value);
  };

  const handleUpload = (event: ChangeEvent<HTMLInputElement>) => {
    const file = event.target.files?.[0];
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
    <Card title={t_i18n('Map tiles')}>
      <List style={{ marginTop: -20 }}>
        <ListItem divider={true}>
          <ListItemText primary={t_i18n('Source')} />
          <Select
            variant="standard"
            size="small"
            value={mode}
            onChange={handleModeChange}
          >
            <MenuItem value="bundled">{t_i18n('Bundled')}</MenuItem>
            <MenuItem value="s3">{t_i18n('Custom (S3)')}</MenuItem>
          </Select>
        </ListItem>
        <ListItem divider={true}>
          <ListItemText primary={t_i18n('Custom file')} />
          {s3File ? (
            <div style={{ textAlign: 'right' }}>
              <Typography variant="body2">
                {s3File.name} ({formatBytes(s3File.size)})
              </Typography>
              {s3File.sha256 && (
                <Typography variant="caption" color="textSecondary" sx={{ fontFamily: 'monospace', fontSize: '0.65rem' }}>
                  (sha256 {s3File.sha256})
                </Typography>
              )}
            </div>
          ) : (
            <Typography variant="body2" color="textSecondary">
              {t_i18n('None')}
            </Typography>
          )}
        </ListItem>
        <ListItem>
          <ListItemText primary={t_i18n('File management')} />
          {s3File ? (
            <>
              <Button
                component="label"
                variant="outlined"
                size="small"
                startIcon={<CloudUploadOutlined />}
                disabled={uploading}
                sx={{ marginRight: 1 }}
              >
                {t_i18n('Replace')}
                <input type="file" hidden accept=".pmtiles" onChange={handleUpload} />
              </Button>
              <Button
                variant="outlined"
                size="small"
                color="error"
                startIcon={<DeleteOutlined />}
                onClick={handleDelete}
              >
                {t_i18n('Delete')}
              </Button>
            </>
          ) : (
            <Button
              component="label"
              variant="outlined"
              size="small"
              startIcon={<CloudUploadOutlined />}
              disabled={uploading}
            >
              {uploading ? t_i18n('Uploading...') : t_i18n('Upload')}
              <input type="file" hidden accept=".pmtiles" onChange={handleUpload} />
            </Button>
          )}
        </ListItem>
      </List>
    </Card>
  );
};

export default SettingsMapTile;
