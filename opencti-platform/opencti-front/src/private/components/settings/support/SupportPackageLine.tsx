import React, { FunctionComponent } from 'react';
import { graphql, useFragment } from 'react-relay';
import { SupportPackageLine_node$key } from '@components/settings/support/__generated__/SupportPackageLine_node.graphql';
import ListItemText from '@mui/material/ListItemText';
import ListItem from '@mui/material/ListItem';
import ListItemIcon from '@mui/material/ListItemIcon';
import { FileOutline } from 'mdi-material-ui';
import IconButton from '@common/button/IconButton';
import { DeleteOutlined, DownloadingOutlined, GetAppOutlined } from '@mui/icons-material';
import Tooltip from '@mui/material/Tooltip';
import { RecordSourceSelectorProxy } from 'relay-runtime';
import CircularProgress from '@mui/material/CircularProgress';
import Chip from '@mui/material/Chip';
import { SupportPackageLineForceZipMutation$data } from '@components/settings/support/__generated__/SupportPackageLineForceZipMutation.graphql';
import { APP_BASE_PATH, handleError, MESSAGING$ } from '../../../../relay/environment';
import { useFormatter } from '../../../../components/i18n';
import { deleteNode } from '../../../../utils/store';
import { hexToRGB } from '../../../../utils/Colors';
import { DataColumns } from '../../../../components/list_lines';
import useApiMutation from '../../../../utils/hooks/useApiMutation';
import { minutesBetweenDates, now } from '../../../../utils/Time';
import DeleteDialog from '../../../../components/DeleteDialog';
import useDeletion from '../../../../utils/hooks/useDeletion';
import { chipInListBasicStyle } from '../../../../utils/chipStyle';

const styles = {
  bodyItem: {
    height: 20,
    fontSize: 13,
    float: 'left' as 'left' | 'right' | 'none' | undefined,
    whiteSpace: 'nowrap',
    overflow: 'hidden',
    textOverflow: 'ellipsis',
    paddingRight: 10,
  },
  item: {
    paddingLeft: 10,
    height: 50,
    cursor: 'default',
  },
  chipInList: {
    ...chipInListBasicStyle,
    width: 120,
  },
  label: {
    whiteSpace: 'nowrap',
    overflow: 'hidden',
    textOverflow: 'ellipsis',
  },
};

type PackageStatus = 'IN_PROGRESS' | 'READY' | 'IN_ERROR' | 'TIMEOUT' | '%future added value';

const SupportPackageLineForceZipMutation = graphql`
  mutation SupportPackageLineForceZipMutation(    
    $input: SupportPackageForceZipInput!
  ) {
      supportPackageForceZip(input: $input) {
        id
        package_url
      }
  }
`;

const SupportPackageLineDeleteMutation = graphql`
  mutation SupportPackageLineDeleteMutation($id: ID!) {
    supportPackageDelete(id: $id)
  }
`;

export const supportPackageLineFragment = graphql`
  fragment SupportPackageLine_node on SupportPackage {
    id
    name
    package_status
    package_url
    package_upload_dir
    created_at
    creators {
      id
      name
    }
  }
`;

const packageStatusColors: { [key in PackageStatus]: string } = {
  IN_PROGRESS: '#303f9f',
  READY: '#4caf50',
  IN_ERROR: '#f44336',
  TIMEOUT: '#f44336',
  '%future added value': '#9e9e9e',
};

interface SupportPackageLineProps {
  dataColumns: DataColumns;
  node: SupportPackageLine_node$key;
  paginationOptions: { search: string; orderMode: string; orderBy: string };
}

const SupportPackageLine: FunctionComponent<SupportPackageLineProps> = ({
  node,
  paginationOptions,
  dataColumns,
}) => {
  const { t_i18n, fndt } = useFormatter();
  const data = useFragment(supportPackageLineFragment, node);
  const [commitDelete] = useApiMutation(SupportPackageLineDeleteMutation);
  const [commitForceZip] = useApiMutation(SupportPackageLineForceZipMutation);
  const isProgress = data.package_status === 'IN_PROGRESS';
  const isReady = data.package_status === 'READY';
  const isTooLong = minutesBetweenDates(data.created_at, now()) > 1;
  const isTimeout = !isReady && minutesBetweenDates(data.created_at, now()) > 5;
  const finalStatus = isTimeout ? 'TIMEOUT' : data.package_status;

  const deletion = useDeletion({});
  const { setDeleting, handleOpenDelete, handleCloseDelete } = deletion;
  const submitDelete = () => {
    setDeleting(true);
    commitDelete({
      variables: {
        id: data.id,
      },
      updater: (store: RecordSourceSelectorProxy) => deleteNode(
        store,
        'Pagination_supportPackages',
        paginationOptions,
        data.id,
      ),
      onCompleted: () => {
        setDeleting(false);
        handleCloseDelete();
      },
      onError: (error: Error) => {
        setDeleting(false);
        handleError(error);
      },
    });
  };

  const handleForceZip = () => {
    commitForceZip({
      variables: {
        input: {
          id: data.id,
        },
      },
      onCompleted: (response) => {
        const res = response as SupportPackageLineForceZipMutation$data;
        // Check if there is a valid URL and initiate download
        if (res.supportPackageForceZip?.package_url) {
          MESSAGING$.notifySuccess('Force zip launched. Your download will start shortly.');
          window.location.href = `${APP_BASE_PATH}/storage/get/${encodeURIComponent(res.supportPackageForceZip.package_url)}`;
        } else {
          MESSAGING$.notifyError('No download URL available.');
        }
      },
    });
  };

  return (
    <>
      <ListItem
        divider={true}
        style={{ ...styles.item }}
        secondaryAction={(
          <>
            {!isReady && (
              <Tooltip title={t_i18n('Force download on this support package')}>
                <span>
                  <IconButton disabled={!isTooLong} onClick={handleForceZip}>
                    <DownloadingOutlined fontSize="small" />
                  </IconButton>
                </span>
              </Tooltip>
            )}
            {isReady && (
              <Tooltip title={t_i18n('Download this support package')}>
                <span>
                  <IconButton
                    disabled={!data.package_url}
                    href={`${APP_BASE_PATH}/storage/get/${encodeURIComponent(
                      data.package_url || '',
                    )}`}
                  >
                    <GetAppOutlined fontSize="small" />
                  </IconButton>
                </span>
              </Tooltip>
            )}
            <Tooltip title={t_i18n('Delete this support package')}>
              <span>
                <IconButton
                  disabled={!isReady && !isTooLong}
                  // color='inherit'
                  onClick={handleOpenDelete}
                  size="small"
                >
                  <DeleteOutlined fontSize="small" />
                </IconButton>
              </span>
            </Tooltip>
          </>
        )}
      >
        <ListItemIcon>
          {isProgress && !isTimeout && (
            <CircularProgress
              size={20}
              color="inherit"
            />
          )}
          {isProgress && isTimeout && (
            <FileOutline
              color="inherit"
            />
          )}
          {!isProgress && (
            <FileOutline
              color="inherit"
            />
          )}
        </ListItemIcon>
        <ListItemText
          primary={(
            <>
              <div style={{ width: dataColumns.name.width, ...styles.bodyItem }}>
                {data.name}
              </div>
              <div style={{ width: dataColumns.package_status.width, ...styles.bodyItem, paddingLeft: 15 }}>
                <Chip
                  style={{
                    color: packageStatusColors[finalStatus],
                    borderColor: packageStatusColors[finalStatus],
                    backgroundColor: hexToRGB(packageStatusColors[finalStatus]),
                    ...styles.chipInList,
                    ...styles.label,
                  }}
                  label={t_i18n(finalStatus)}
                />
              </div>
              <div
                style={{ width: dataColumns.created_at.width, ...styles.bodyItem, paddingLeft: 20 }}
              >
                {fndt(data.created_at)}
              </div>
            </>
          )}
        />
      </ListItem>
      <DeleteDialog
        deletion={deletion}
        submitDelete={submitDelete}
        message={t_i18n('Do you want to delete this support package?')}
      />
    </>
  );
};

export default SupportPackageLine;
