import React, { useState } from 'react';
import Menu from '@mui/material/Menu';
import MenuItem from '@mui/material/MenuItem';
import MoreVert from '@mui/icons-material/MoreVert';
import ToggleButton from '@mui/material/ToggleButton';
import StixCoreObjectEnrichment from '../../common/stix_core_objects/StixCoreObjectEnrichment';
import { useFormatter } from '../../../../components/i18n';
import { reportEditionQuery } from './ReportEdition';
import ReportEditionContainer from './ReportEditionContainer';
import { KnowledgeSecurity } from '../../../../utils/Security';
import { KNOWLEDGE_KNENRICHMENT, KNOWLEDGE_KNUPDATE, KNOWLEDGE_KNUPDATE_KNDELETE } from '../../../../utils/hooks/useGranted';
import { QueryRenderer } from '../../../../relay/environment';
import ReportPopoverDeletion from './ReportPopoverDeletion';

const ReportPopover = ({ id }) => {
  const { t_i18n } = useFormatter();
  const [anchorEl, setAnchorEl] = useState(null);
  const [displayDelete, setDisplayDelete] = useState(false);
  const [displayEdit, setDisplayEdit] = useState(false);
  const [displayEnrichment, setDisplayEnrichment] = useState(false);
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
  return (
    <div>
      <KnowledgeSecurity needs={[KNOWLEDGE_KNUPDATE, KNOWLEDGE_KNUPDATE_KNDELETE]} entity='Report'>
        <ToggleButton
          value="popover"
          size="small"
          onClick={handleOpen}
        >
          <MoreVert fontSize="small" color="primary" />
        </ToggleButton>
        <Menu anchorEl={anchorEl} open={Boolean(anchorEl)} onClose={handleClose}>
          <KnowledgeSecurity needs={[KNOWLEDGE_KNUPDATE]} entity='Report'>
            <MenuItem onClick={handleOpenEdit}>{t_i18n('Update')}</MenuItem>
          </KnowledgeSecurity>
          <KnowledgeSecurity needs={[KNOWLEDGE_KNENRICHMENT]} entity='Report'>
            <MenuItem onClick={handleOpenEnrichment}>{t_i18n('Enrich')}</MenuItem>
          </KnowledgeSecurity>
          <KnowledgeSecurity needs={[KNOWLEDGE_KNUPDATE_KNDELETE]} entity='Report'>
            <MenuItem onClick={handleOpenDelete}>{t_i18n('Delete')}</MenuItem>
          </KnowledgeSecurity>
        </Menu>
        <StixCoreObjectEnrichment stixCoreObjectId={id} open={displayEnrichment} handleClose={handleCloseEnrichment} />
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
      </KnowledgeSecurity>
    </div>
  );
};

export default ReportPopover;
