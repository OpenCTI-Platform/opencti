import React, { ChangeEvent, FunctionComponent, ReactNode, useState } from 'react';
import { graphql } from 'react-relay';
import type { PayloadError } from 'relay-runtime';
import Button from '../../../../components/common/button/Button';
import List from '@mui/material/List';
import ListItem from '@mui/material/ListItem';
import ListItemText from '@mui/material/ListItemText';
import Typography from '@mui/material/Typography';
import { CloudUploadOutlined, DeleteOutlined, DownloadOutlined } from '@mui/icons-material';
import Card from '../../../../components/common/card/Card';
import { useFormatter } from '../../../../components/i18n';
import useApiMutation from '../../../../utils/hooks/useApiMutation';
import { APP_BASE_PATH, MESSAGING$ } from '../../../../relay/environment';
import { invalidateCountries } from '../../common/location/countries';
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

const uploadCountriesCustomFileMutation = graphql`
  mutation SettingsMapSourceUploadCountriesMutation($id: ID!, $file: Upload!) {
    settingsEdit(id: $id) {
      uploadCountriesCustomFile(file: $file) {
        id
        platform_map_countries_custom_file {
          name
          size
        }
      }
    }
  }
`;

const deleteCountriesCustomFileMutation = graphql`
  mutation SettingsMapSourceDeleteCountriesMutation($id: ID!) {
    settingsEdit(id: $id) {
      deleteCountriesCustomFile {
        id
        platform_map_countries_custom_file {
          name
          size
        }
      }
    }
  }
`;

interface CustomFile {
  readonly name: string;
  readonly size: number;
}

interface SettingsMapSourceFileProps {
  label: string;
  emptyLabel: string;
  accept: string;
  downloadUrl: string;
  customFile: CustomFile | null | undefined;
  divider?: boolean;
  onUpload: (file: File) => void;
  onDelete: () => void;
  uploading: boolean;
}

const SettingsMapSourceFile: FunctionComponent<SettingsMapSourceFileProps> = ({
  label,
  emptyLabel,
  accept,
  downloadUrl,
  customFile,
  divider,
  onUpload,
  onDelete,
  uploading,
}) => {
  const { t_i18n, b: formatBytes } = useFormatter();

  const handleUpload = (event: ChangeEvent<HTMLInputElement>) => {
    const file = event.target.files?.[0];
    event.target.value = '';
    if (file) onUpload(file);
  };

  return (
    <ListItem divider={divider}>
      <ListItemText primary={label} />
      <div>
        <Typography variant="body2" sx={{ marginBottom: 1 }}>
          {customFile
            ? `${customFile.name} (${formatBytes(customFile.size)})`
            : emptyLabel}
        </Typography>
        <div style={{ display: 'flex', gap: 8 }}>
          {customFile && (
            <Button
              variant="secondary"
              size="small"
              startIcon={<DownloadOutlined />}
              href={downloadUrl}
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
            <input type="file" hidden accept={accept} onChange={handleUpload} />
          </Button>
          {customFile && (
            <Button
              variant="secondary"
              size="small"
              color="error"
              startIcon={<DeleteOutlined />}
              onClick={onDelete}
            >
              {t_i18n('Delete')}
            </Button>
          )}
        </div>
      </div>
    </ListItem>
  );
};

interface SettingsMapSourceProps {
  settings: SettingsQuery$data['settings'] & { readonly id: string };
}

const SettingsMapSource: FunctionComponent<SettingsMapSourceProps> = ({
  settings,
}) => {
  const { t_i18n } = useFormatter();
  const [uploadingMap, setUploadingMap] = useState(false);
  const [uploadingCountries, setUploadingCountries] = useState(false);

  // A rejected upload is reported through the second argument of onCompleted, not through
  // onError, which only fires on transport failures.
  const settleUpload = (setUploading: (value: boolean) => void, onChanged?: () => void) => ({
    onCompleted: (_: unknown, errors: readonly PayloadError[] | null) => {
      setUploading(false);
      if (errors && errors.length > 0) {
        MESSAGING$.notifyError(errors[0].message);
        return;
      }
      onChanged?.();
    },
    onError: () => setUploading(false),
  });

  const [commitUploadMap] = useApiMutation(uploadMapCustomFileMutation);
  const [commitDeleteMap] = useApiMutation(deleteMapCustomFileMutation);
  const [commitUploadCountries] = useApiMutation(uploadCountriesCustomFileMutation);
  const [commitDeleteCountries] = useApiMutation(deleteCountriesCustomFileMutation);

  const rows: ReactNode[] = [
    <SettingsMapSourceFile
      key="map"
      label={t_i18n('Custom map')}
      emptyLabel={t_i18n('No custom map uploaded, using the bundled map')}
      accept=".pmtiles"
      downloadUrl={`${APP_BASE_PATH}/maps/world.pmtiles`}
      customFile={settings.platform_map_custom_file}
      divider={true}
      uploading={uploadingMap}
      onUpload={(file) => {
        setUploadingMap(true);
        commitUploadMap({
          variables: { id: settings.id, file },
          ...settleUpload(setUploadingMap),
        });
      }}
      onDelete={() => commitDeleteMap({ variables: { id: settings.id } })}
    />,
    <SettingsMapSourceFile
      key="countries"
      label={t_i18n('Custom country boundaries')}
      emptyLabel={t_i18n('No custom country boundaries uploaded, using the bundled ones')}
      accept=".json,.gz,.geojson"
      downloadUrl={`${APP_BASE_PATH}/maps/countries.json`}
      customFile={settings.platform_map_countries_custom_file}
      uploading={uploadingCountries}
      onUpload={(file) => {
        setUploadingCountries(true);
        commitUploadCountries({
          variables: { id: settings.id, file },
          ...settleUpload(setUploadingCountries, invalidateCountries),
        });
      }}
      onDelete={() => commitDeleteCountries({
        variables: { id: settings.id },
        onCompleted: () => invalidateCountries(),
      })}
    />,
  ];

  return (
    <Card title={t_i18n('Map configuration')}>
      <List style={{ marginTop: -20 }}>{rows}</List>
    </Card>
  );
};

export default SettingsMapSource;
