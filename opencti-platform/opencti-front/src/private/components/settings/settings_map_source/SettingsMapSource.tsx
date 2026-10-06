import React, { ChangeEvent, FunctionComponent, useState } from 'react';
import { graphql } from 'react-relay';
import Button from '../../../../components/common/button/Button';
import Typography from '@mui/material/Typography';
import { CloudUploadOutlined, DeleteOutlined, DownloadOutlined } from '@mui/icons-material';
import SettingsInfoRow from '../settings_platform/SettingsInfoRow';
import DeleteDialog from '../../../../components/DeleteDialog';
import { useFormatter } from '../../../../components/i18n';
import useApiMutation from '../../../../utils/hooks/useApiMutation';
import useDeletion from '../../../../utils/hooks/useDeletion';
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
  const deletion = useDeletion({});

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

  const submitDelete = () => {
    deletion.setDeleting(true);
    commitDelete({
      variables: { id: settings.id },
      onCompleted: () => {
        deletion.setDeleting(false);
        deletion.handleCloseDelete();
      },
      onError: () => deletion.setDeleting(false),
    });
  };

  const caption = customFile
    ? `${customFile.name} (${formatBytes(customFile.size)})`
    : t_i18n('No custom map uploaded, using the bundled map');

  // Rendered as the last row of the Appearance card of the Parameters page.
  return (
    <>
      <SettingsInfoRow divider={false} size="field" label={t_i18n('Custom map')} data-testid="settings-map-source">
        <Typography
          variant="body2"
          color="textSecondary"
          title={caption}
          sx={{ minWidth: 0, whiteSpace: 'nowrap', overflow: 'hidden', textOverflow: 'ellipsis' }}
        >
          {caption}
        </Typography>
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
          // keepMui: the 26 px of the Upload label and the Download link, which cannot render through the library
          <Button
            variant="secondary"
            size="small"
            color="error"
            keepMui
            startIcon={<DeleteOutlined />}
            onClick={deletion.handleOpenDelete}
          >
            {t_i18n('Delete')}
          </Button>
        )}
      </SettingsInfoRow>
      <DeleteDialog
        deletion={deletion}
        submitDelete={submitDelete}
        message={t_i18n('Do you want to delete the custom map? The bundled map will be used again.')}
      />
    </>
  );
};

export default SettingsMapSource;
