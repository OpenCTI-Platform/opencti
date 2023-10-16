import React, { useState } from 'react';
import Menu from '@mui/material/Menu';
import MenuItem from '@mui/material/MenuItem';
import IconButton from '@mui/material/IconButton';
import MoreVert from '@mui/icons-material/MoreVert';
import makeStyles from '@mui/styles/makeStyles';
import { useFormatter } from '../../../../components/i18n';
import { reportEditionQuery } from './ReportEdition';
import ReportEditionContainer from './ReportEditionContainer';
import Loader from '../../../../components/Loader';
import Security from '../../../../utils/Security';
import { KNOWLEDGE_KNUPDATE_KNDELETE } from '../../../../utils/hooks/useGranted';
import { QueryRenderer } from '../../../../relay/environment';
import ReportPopoverDeletion from './ReportPopoverDeletion';

const useStyles = makeStyles(() => ({
  container: {
    margin: 0,
  },
}));

const ReportPopover = ({ id }) => {
  const classes = useStyles();
  const { t } = useFormatter();
  const [anchorEl, setAnchorEl] = useState(null);
  const [displayDelete, setDisplayDelete] = useState(false);
  const [displayEdit, setDisplayEdit] = useState(false);
  const handleOpen = (event) => setAnchorEl(event.currentTarget);
  const handleClose = () => setAnchorEl(null);
  const handleOpenDelete = () => {
    setDisplayDelete(true);
    handleClose();
  };
  const handleCloseDelete = () => {
    setDisplayDelete(false);
  };
  const handleOpenEdit = () => {
    setDisplayEdit(true);
    handleClose();
  };
  const handleCloseEdit = () => setDisplayEdit(false);
  return (
    <div className={classes.container}>
      <IconButton
        onClick={handleOpen}
        aria-haspopup="true"
        style={{ marginTop: 3 }}
        size="large"
      >
        <MoreVert />
      </IconButton>
      <Menu anchorEl={anchorEl} open={Boolean(anchorEl)} onClose={handleClose}>
        <MenuItem onClick={handleOpenEdit}>{t('Update')}</MenuItem>
        <Security needs={[KNOWLEDGE_KNUPDATE_KNDELETE]}>
          <MenuItem onClick={handleOpenDelete}>{t('Delete')}</MenuItem>
        </Security>
      </Menu>
      <ReportPopoverDeletion
        reportId={id}
        displayDelete={displayDelete}
        handleClose={handleClose}
        handleCloseDelete={handleCloseDelete}
      />
      <QueryRenderer
        query={reportEditionQuery}
        variables={{ id }}
        render={({ props }) => {
          if (props) {
            return (
              <ReportEditionContainer
                report={props.report}
                handleClose={handleCloseEdit}
                open={displayEdit}
              />
            );
          }
          return <Loader variant="inElement" />;
        }}
      />
    </div>
  );
};

export default ReportPopover;
