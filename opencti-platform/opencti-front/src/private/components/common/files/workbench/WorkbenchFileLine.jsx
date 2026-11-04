import React from 'react';
import * as PropTypes from 'prop-types';
import { createFragmentContainer } from 'react-relay';
import IconButton from '@common/button/IconButton';
import { FileOutline } from 'mdi-material-ui';
import { DeleteOutlined, GetAppOutlined, WarningOutlined } from '@mui/icons-material';
import Tooltip from '@mui/material/Tooltip';
import ListItemIcon from '@mui/material/ListItemIcon';
import ListItemText from '@mui/material/ListItemText';
import CircularProgress from '@mui/material/CircularProgress';
import { Link } from 'react-router';
import Slide from '@mui/material/Slide';
import { Chip } from '@filigran/design-system';
import { ListItemButton } from '@mui/material';
import { styled, useTheme } from '@mui/material/styles';
import ListItem from '@mui/material/ListItem';
import { WorkbenchFileLineDeleteMutation, workbenchLineFragment } from '../../../data/import/ImportWorkbenchesContent';
import FileWork from '../FileWork';
import { useFormatter } from '../../../../../components/i18n';
import { APP_BASE_PATH, commitMutation, MESSAGING$ } from '../../../../../relay/environment';
import { toB64 } from '../../../../../utils/String';
import useAuth from '../../../../../utils/hooks/useAuth';
import ItemMarkings from '../../../../../components/ItemMarkings';
import DeleteDialog from '../../../../../components/DeleteDialog';
import useDeletion from '../../../../../utils/hooks/useDeletion';
import FieldOrEmpty from '../../../../../components/FieldOrEmpty';
import { bodyItemStyle } from '../../../../../components/list_lines/listLineStyles';

const BodyItem = styled('div')(bodyItemStyle);

// `text-overflow` never reaches bare text in a flex container; it only ellipsises a real child.
const BodyItemText = styled('span')({
  overflow: 'hidden',
  textOverflow: 'ellipsis',
  whiteSpace: 'nowrap',
});

const inlineStyles = {
  name: {
    width: '28%',
  },
  creator_name: {
    width: '15%',
  },
  labels: {
    width: '12%',
    display: 'flex',
    alignItems: 'center',
  },
  // A track too short for "PAP:AMBER" squeezes the chip instead of shortening it.
  markings: {
    width: '24%',
    display: 'flex',
    alignItems: 'center',
    paddingRight: 16,
  },
  lastModified: {
    width: '16%',
  },
};

const Transition = React.forwardRef((props, ref) => (
  <Slide direction="up" ref={ref} {...props} />
));
Transition.displayName = 'TransitionSlide';

const WorkbenchFileLineComponent = ({ file, dense, directDownload, nested }) => {
  const theme = useTheme();
  const { t_i18n, ftdt } = useFormatter();
  const { me } = useAuth();
  const deletion = useDeletion({});
  const { handleOpenDelete, handleCloseDelete } = deletion;

  const executeRemove = (mutation, variables) => {
    commitMutation({
      mutation,
      variables,
      optimisticUpdater: (store) => {
        const fileStore = store.get(file.id);
        fileStore.setValue(0, 'lastModifiedSinceMin');
        fileStore.setValue('progress', 'uploadStatus');
      },
      updater: (store) => {
        const fileStore = store.get(file.id);
        fileStore.setValue(0, 'lastModifiedSinceMin');
        fileStore.setValue('progress', 'uploadStatus');
      },
      onCompleted: () => {
        MESSAGING$.notifySuccess(t_i18n('File successfully removed'));
      },
    });
  };

  const handleRemoveFile = () => {
    executeRemove(WorkbenchFileLineDeleteMutation, { fileName: file.id });
    handleCloseDelete();
  };

  const { uploadStatus, metaData } = file;
  const { errors } = metaData;
  const isFail = errors && errors.length > 0;
  const isProgress = uploadStatus === 'progress' || uploadStatus === 'wait';
  const isOutdated = uploadStatus === 'timeout';
  const file_markings = (file.objectMarking ?? []).map((o) => o.id);
  const fileMarkings = me.allowed_marking?.filter(({ id }) => (file_markings ?? []).includes(id)) ?? [];
  return (
    <>
      <ListItem
        divider={true}
        dense={dense === true}
        disablePadding
        secondaryAction={(
          <>
            {!directDownload && !isFail && (
              <Tooltip title={t_i18n('Download this file')}>
                <IconButton
                  disabled={isProgress}
                  href={`${APP_BASE_PATH}/storage/get/${encodeURIComponent(
                    file.id,
                  )}`}
                  aria-haspopup="true"
                  color={nested ? 'inherit' : 'primary'}
                  size="small"
                  keepMui
                  aria-label={t_i18n('Download this file')}
                >
                  <GetAppOutlined fontSize="small" />
                </IconButton>
              </Tooltip>
            )}
            <Tooltip title={t_i18n('Delete this workbench')}>
              <IconButton
                disabled={isProgress}
                color={nested ? 'inherit' : 'primary'}
                onClick={handleOpenDelete}
                size="small"
                keepMui
                aria-label={t_i18n('Delete this workbench')}
              >
                <DeleteOutlined fontSize="small" />
              </IconButton>
            </Tooltip>
          </>
        )}
      >
        <ListItemButton
          sx={nested ? { paddingLeft: 4, height: 50 } : { paddingLeft: '10px', height: 50 }}
          component={isOutdated ? null : Link}
          disabled={isProgress}
          to={`/dashboard/data/import/workbench/${toB64(file.id)}`}
        >
          <ListItemIcon>
            {isProgress && (
              <CircularProgress
                size={20}
                color={nested ? 'primary' : 'inherit'}
              />
            )}
            {!isProgress && (isFail || isOutdated) && (
              <WarningOutlined
                color={nested ? 'primary' : 'inherit'}
                style={{ fontSize: 15, color: theme.palette.error.main }}
              />
            )}
            {!isProgress && !isFail && !isOutdated && (
              <FileOutline color={nested ? 'primary' : 'inherit'} />
            )}
          </ListItemIcon>
          <ListItemText
            primary={(
              <>
                <BodyItem style={inlineStyles.name}>
                  <BodyItemText>{file.name.replace('.json', '')}</BodyItemText>
                </BodyItem>
                <FieldOrEmpty source={file.metaData.creator?.name}>
                  <BodyItem style={inlineStyles.creator_name}>
                    <BodyItemText>{file.metaData.creator?.name}</BodyItemText>
                  </BodyItem>
                </FieldOrEmpty>
                <BodyItem style={inlineStyles.labels}>
                  {file.metaData.labels_text ? file.metaData.labels_text.split(';').map((label, index) => (
                    <Chip
                      key={index}
                      severity="info"
                      label={label.trim()}
                    />
                  )) : null}
                </BodyItem>
                <BodyItem style={inlineStyles.markings}>
                  <ItemMarkings variant="inList" markingDefinitions={fileMarkings} limit={1} />
                </BodyItem>
                <BodyItem style={inlineStyles.lastModified}>
                  <BodyItemText>{ftdt(file.lastModified)}</BodyItemText>
                </BodyItem>
              </>
            )}
          />
        </ListItemButton>
      </ListItem>

      <FileWork file={file} />
      <DeleteDialog
        deletion={deletion}
        submitDelete={handleRemoveFile}
        message={t_i18n('Do you want to delete this workbench?')}
      />
    </>
  );
};

WorkbenchFileLineComponent.propTypes = {
  t: PropTypes.func,
  fld: PropTypes.func,
  file: PropTypes.object.isRequired,
  connectors: PropTypes.array,
  dense: PropTypes.bool,
  directDownload: PropTypes.bool,
  nested: PropTypes.bool,
};

const WorkbenchFileLine = createFragmentContainer(WorkbenchFileLineComponent, {
  file: workbenchLineFragment,
});

export default WorkbenchFileLine;
