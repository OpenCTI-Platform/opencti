import React, { useState } from 'react';
import Menu from '@mui/material/Menu';
import MenuItem from '@mui/material/MenuItem';
import MoreVert from '@mui/icons-material/MoreVert';
import ToggleButton from '@mui/material/ToggleButton';
import ReportPopoverDeletion from './ReportPopoverDeletion';
import StixCoreObjectEnrichment from '../../common/stix_core_objects/StixCoreObjectEnrichment';
import StixCoreObjectEnrollPlaybook from '../../common/stix_core_objects/StixCoreObjectEnrollPlaybook';
import { useFormatter } from '../../../../components/i18n';
import { reportEditionQuery } from './ReportEdition';
import ReportEditionContainer from './ReportEditionContainer';
import Security from '../../../../utils/Security';
import { KNOWLEDGE_KNENRICHMENT, KNOWLEDGE_KNUPDATE_KNDELETE } from '../../../../utils/hooks/useGranted';
import { QueryRenderer } from '../../../../relay/environment';
import useHelper from '../../../../utils/hooks/useHelper';

const ReportPopover = ({ id }) => {
  const { t_i18n } = useFormatter();
  const [anchorEl, setAnchorEl] = useState(null);
  const [displayDelete, setDisplayDelete] = useState(false);
  const [displayEdit, setDisplayEdit] = useState(false);
  const [displayEnrichment, setDisplayEnrichment] = useState(false);
  const [displayEnroll, setDisplayEnroll] = useState(false);

  const { isFeatureEnable } = useHelper();
  const isFABReplaced = isFeatureEnable('FAB_REPLACEMENT');

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
  const handleOpenEnrichment = () => {
    setDisplayEnrichment(true);
    handleClose();
  };
  const handleCloseEnrichment = () => {
    setDisplayEnrichment(false);
  };
  const handleOpenEnroll = () => {
    setDisplayEnroll(true);
    handleClose();
  };
  const handleCloseEnroll = () => {
    setDisplayEnroll(false);
  };
  return isFABReplaced
    ? (<></>)
    : (
      <>
        <ToggleButton
          value="popover"
          size="small"
          onClick={handleOpen}
          title={t_i18n('Report actions')}
        >
          <MoreVert fontSize="small" color="primary" />
        </ToggleButton>
        <Menu anchorEl={anchorEl} open={Boolean(anchorEl)} onClose={handleClose}>
          <MenuItem onClick={handleOpenEdit}>{t_i18n('Update')}</MenuItem>
          <Security needs={[KNOWLEDGE_KNENRICHMENT]}>
            <MenuItem onClick={handleOpenEnrichment}>{t_i18n('Enrich')}</MenuItem>
          </Security>
          <Security needs={[KNOWLEDGE_KNENRICHMENT]}>
            <MenuItem onClick={handleOpenEnroll}>{t_i18n('Enroll in playbook')}</MenuItem>
          </Security>
          <Security needs={[KNOWLEDGE_KNUPDATE_KNDELETE]}>
            <MenuItem onClick={handleOpenDelete}>{t_i18n('Delete')}</MenuItem>
          </Security>
        </Menu>
        <StixCoreObjectEnrichment stixCoreObjectId={id} open={displayEnrichment} handleClose={handleCloseEnrichment} />
        <StixCoreObjectEnrollPlaybook stixCoreObjectId={id} open={displayEnroll} handleClose={handleCloseEnroll} />
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
            return <div />;
          }}
        />
      </>
    );
};

export default ReportPopover;
