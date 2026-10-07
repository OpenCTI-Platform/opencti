import React, { ChangeEvent, FunctionComponent, ReactNode, useRef, useState } from 'react';
import { graphql } from 'react-relay';
import type { PayloadError } from 'relay-runtime';
import { Link } from 'react-router';
import { useIntl } from 'react-intl';
import { useTheme } from '@mui/styles';
import List from '@mui/material/List';
import ListItem from '@mui/material/ListItem';
import { Chip, IconButton, Menu, MenuContent, MenuItem, MenuSeparator, MenuTrigger, Text } from '@filigran/design-system';
import { AutorenewOutlined, CloudUploadOutlined, DeleteOutlined, DownloadOutlined, InfoOutlined, InsertDriveFileOutlined, MoreVert, OpenInNewOutlined } from '@mui/icons-material';
import Card from '../../../../components/common/card/Card';
import DeleteDialog from '../../../../components/DeleteDialog';
import ItemBoolean from '../../../../components/ItemBoolean';
import type { Theme } from '../../../../components/Theme';
import { useFormatter } from '../../../../components/i18n';
import Security from '../../../../utils/Security';
import { SETTINGS_SETPARAMETERS } from '../../../../utils/hooks/useGranted';
import useApiMutation from '../../../../utils/hooks/useApiMutation';
import useDeletion from '../../../../utils/hooks/useDeletion';
import { APP_BASE_PATH, MESSAGING$ } from '../../../../relay/environment';
import { invalidateCountries } from '../../common/location/countries';
import { SettingsQuery$data } from '../__generated__/SettingsQuery.graphql';
import { bytesFormat } from '../../../../utils/Number';

const MAP_DOCUMENTATION_URL = 'https://docs.opencti.io/latest/deployment/advanced/map/';
const SECONDARY_TEXT_COLOR = 'var(--text-default-secondary)';
const SMALL_ICON_SIZE = 'var(--text-3)';

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
  defaultLabel: string;
  deleteMessage: string;
  accept: string;
  downloadUrl: string;
  customFile: CustomFile | null | undefined;
  divider?: boolean;
  onUpload: (file: File) => void;
  onDelete: (onSettled: () => void) => void;
  uploading: boolean;
}

const SettingsMapSourceFile: FunctionComponent<SettingsMapSourceFileProps> = ({
  label,
  defaultLabel,
  deleteMessage,
  accept,
  downloadUrl,
  customFile,
  divider,
  onUpload,
  onDelete,
  uploading,
}) => {
  const { t_i18n } = useFormatter();
  const intl = useIntl();
  const theme = useTheme<Theme>();
  const [menuOpen, setMenuOpen] = useState(false);
  const fileInputRef = useRef<HTMLInputElement>(null);
  const deletion = useDeletion({});

  const handleFileChange = (event: ChangeEvent<HTMLInputElement>) => {
    const file = event.target.files?.[0];
    event.target.value = '';
    if (file) onUpload(file);
  };

  const submitDelete = () => {
    deletion.setDeleting(true);
    onDelete(() => {
      deletion.setDeleting(false);
      deletion.handleCloseDelete();
    });
  };

  let secondary: ReactNode = defaultLabel;
  if (uploading) {
    secondary = t_i18n('Uploading...');
  } else if (customFile) {
    const size = bytesFormat(customFile.size);
    secondary = (
      <>
        <InsertDriveFileOutlined fontSize="inherit" />
        {`${customFile.name} · ${intl.formatNumber(size.number)} ${size.symbol.trim()}`}
      </>
    );
  }

  return (
    <ListItem divider={divider} sx={{ pl: 1, pr: 2, py: 0.75 }}>
      <div style={{ flex: 1, minWidth: 0 }}>
        <Text variant="content-base">{label}</Text>
        <Text
          variant="content-compact"
          style={{ display: 'flex', alignItems: 'center', gap: theme.spacing(0.5), color: SECONDARY_TEXT_COLOR }}
        >
          {secondary}
        </Text>
      </div>
      <div style={{ display: 'flex', alignItems: 'center', gap: theme.spacing(1) }}>
        {customFile
          ? <ItemBoolean status={true} label={t_i18n('Custom')} />
          : <Chip label={t_i18n('Default')} />}
        <Security needs={[SETTINGS_SETPARAMETERS]}>
          <Menu open={menuOpen} onOpenChange={setMenuOpen}>
            <MenuTrigger asChild>
              <IconButton
                variant="default"
                priority="tertiary"
                aria-label={`${t_i18n('Open menu')}: ${label}`}
                active={menuOpen}
                disabled={uploading}
                icon={<MoreVert />}
              />
            </MenuTrigger>
            <MenuContent align="end">
              {customFile ? (
                <>
                  <MenuItem asChild startIcon={<DownloadOutlined fontSize="small" />}>
                    <a href={downloadUrl} download={customFile.name}>{t_i18n('Download')}</a>
                  </MenuItem>
                  <MenuItem
                    startIcon={<AutorenewOutlined fontSize="small" />}
                    onSelect={() => fileInputRef.current?.click()}
                  >
                    {t_i18n('Replace')}
                  </MenuItem>
                  <MenuSeparator />
                  {/* FDS-WORKAROUND #64: MenuItem has no destructive tone — see fds-migration/LIBRARY-FEEDBACK.md #64 */}
                  <MenuItem
                    startIcon={<DeleteOutlined fontSize="small" color="error" />}
                    style={{ color: theme.palette.error.main }}
                    onSelect={() => deletion.handleOpenDelete()}
                  >
                    {t_i18n('Delete')}
                  </MenuItem>
                </>
              ) : (
                <MenuItem
                  startIcon={<CloudUploadOutlined fontSize="small" />}
                  onSelect={() => fileInputRef.current?.click()}
                >
                  {t_i18n('Upload')}
                </MenuItem>
              )}
            </MenuContent>
          </Menu>
        </Security>
      </div>
      <input ref={fileInputRef} type="file" hidden accept={accept} onChange={handleFileChange} />
      <DeleteDialog deletion={deletion} submitDelete={submitDelete} message={deleteMessage} />
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
  const theme = useTheme<Theme>();
  const [uploadingMap, setUploadingMap] = useState(false);
  const [uploadingCountries, setUploadingCountries] = useState(false);

  const notifyPayloadErrors = (errors: readonly PayloadError[] | null | undefined) => {
    if (!errors || errors.length === 0) return false;
    MESSAGING$.notifyError(errors[0].message);
    return true;
  };

  const settleUpload = (setUploading: (value: boolean) => void, onChanged?: () => void) => ({
    onCompleted: (_: unknown, errors: readonly PayloadError[] | null | undefined) => {
      setUploading(false);
      if (!notifyPayloadErrors(errors)) onChanged?.();
    },
    onError: () => setUploading(false),
  });

  const settleDelete = (onSettled: () => void, onChanged?: () => void) => ({
    onCompleted: (_: unknown, errors: readonly PayloadError[] | null | undefined) => {
      onSettled();
      if (!notifyPayloadErrors(errors)) onChanged?.();
    },
    onError: () => onSettled(),
  });

  const [commitUploadMap] = useApiMutation(uploadMapCustomFileMutation);
  const [commitDeleteMap] = useApiMutation(deleteMapCustomFileMutation);
  const [commitUploadCountries] = useApiMutation(uploadCountriesCustomFileMutation);
  const [commitDeleteCountries] = useApiMutation(deleteCountriesCustomFileMutation);

  return (
    <Card title={t_i18n('Map configuration')}>
      <List disablePadding>
        <SettingsMapSourceFile
          label={t_i18n('Custom map')}
          defaultLabel={t_i18n('Using the bundled map')}
          deleteMessage={t_i18n('Do you want to delete the custom map?')}
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
          onDelete={(onSettled) => commitDeleteMap({
            variables: { id: settings.id },
            ...settleDelete(onSettled),
          })}
        />
        <SettingsMapSourceFile
          label={t_i18n('Custom country boundaries')}
          defaultLabel={t_i18n('Using the bundled boundaries')}
          deleteMessage={t_i18n('Do you want to delete the custom country boundaries?')}
          accept=".json,.gz,.geojson"
          downloadUrl={`${APP_BASE_PATH}/maps/countries.json`}
          customFile={settings.platform_map_countries_custom_file}
          divider={true}
          uploading={uploadingCountries}
          onUpload={(file) => {
            setUploadingCountries(true);
            commitUploadCountries({
              variables: { id: settings.id, file },
              ...settleUpload(setUploadingCountries, invalidateCountries),
            });
          }}
          onDelete={(onSettled) => commitDeleteCountries({
            variables: { id: settings.id },
            ...settleDelete(onSettled, invalidateCountries),
          })}
        />
      </List>
      <div
        style={{
          display: 'flex',
          alignItems: 'center',
          justifyContent: 'space-between',
          gap: theme.spacing(2),
          marginTop: theme.spacing(2),
          paddingLeft: theme.spacing(1),
          paddingRight: theme.spacing(2),
          color: SECONDARY_TEXT_COLOR,
        }}
      >
        <div style={{ display: 'flex', alignItems: 'center', gap: theme.spacing(1) }}>
          <InfoOutlined style={{ fontSize: SMALL_ICON_SIZE }} />
          <Text variant="content-compact">
            {t_i18n('Changes can take up to 5 minutes to reach every browser.')}
          </Text>
        </div>
        <Text
          as={Link}
          variant="content-compact-link"
          to={MAP_DOCUMENTATION_URL}
          target="_blank"
          rel="noopener noreferrer"
          style={{ display: 'inline-flex', alignItems: 'center', gap: theme.spacing(1), whiteSpace: 'nowrap', color: theme.palette.primary.main }}
        >
          {t_i18n('Learn more')}
          <OpenInNewOutlined style={{ fontSize: SMALL_ICON_SIZE }} />
        </Text>
      </div>
    </Card>
  );
};

export default SettingsMapSource;
