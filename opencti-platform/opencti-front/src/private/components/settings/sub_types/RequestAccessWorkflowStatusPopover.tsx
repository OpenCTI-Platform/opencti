import React, { FunctionComponent, useState } from 'react';
import IconButton from '@mui/material/IconButton';
import MoreVert from '@mui/icons-material/MoreVert';
import Menu from '@mui/material/Menu';
import MenuItem from '@mui/material/MenuItem';
import RequestAccessWorkflowStatusEdit, { requestAccessWorkflowStatusEditQuery, WorkflowStatusEditFormData } from '@components/settings/sub_types/RequestAccessWorkflowStatusEdit';
import useQueryLoading from '../../../../utils/hooks/useQueryLoading';
import { useFormatter } from '../../../../components/i18n';
import { RequestAccessWorkflowStatusEditQuery } from './__generated__/RequestAccessWorkflowStatusEditQuery.graphql';

interface RequestAccessWorkflowStatusPopoverProps {
  entitySettingId: string;
  onStatusChange: (values: WorkflowStatusEditFormData) => void;
}

const RequestAccessWorkflowStatusPopover: FunctionComponent<RequestAccessWorkflowStatusPopoverProps> = ({
  entitySettingId,
  onStatusChange,
}) => {
  const { t_i18n } = useFormatter();
  const queryRef = useQueryLoading<RequestAccessWorkflowStatusEditQuery>(
    requestAccessWorkflowStatusEditQuery,
    { id: entitySettingId },
  );
  const [anchorEl, setAnchorEl] = useState<HTMLElement | null>(null);
  const [displayUpdate, setDisplayUpdate] = useState<boolean>(false);
  const handleOpen = (event: React.MouseEvent<HTMLElement>) => setAnchorEl(event.currentTarget);
  const handleClose = () => setAnchorEl(null);
  const handleOpenUpdate = () => {
    setDisplayUpdate(true);
    handleClose();
  };
  return (
    <>
      <IconButton onClick={handleOpen} aria-haspopup="true" size="large" color="primary">
        <MoreVert />
      </IconButton>
      <Menu anchorEl={anchorEl} open={Boolean(anchorEl)} onClose={handleClose}>
        <MenuItem onClick={handleOpenUpdate}>{t_i18n('Update')}</MenuItem>
      </Menu>
      {queryRef && (
        <React.Suspense fallback={<span />}>
          <RequestAccessWorkflowStatusEdit
            entitySettingId={entitySettingId}
            queryRef={queryRef}
            open={displayUpdate}
            onSubmit={onStatusChange}
          />
        </React.Suspense>
      )}
    </>
  );
};

export default RequestAccessWorkflowStatusPopover;
