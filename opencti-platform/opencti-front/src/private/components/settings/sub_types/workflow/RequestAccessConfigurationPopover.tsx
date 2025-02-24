import { Edit } from '@mui/icons-material';
import IconButton from '@mui/material/IconButton';
import React, { FunctionComponent, useState } from 'react';
import RequestAccessConfigurationEdition from '@components/settings/sub_types/workflow/RequestAccessConfigurationEdition';
import { RequestAccessConfigurationEdition_requestAccess$key } from './__generated__/RequestAccessConfigurationEdition_requestAccess.graphql';

interface RequestAccessWorkflowEditionProps {
  data: RequestAccessConfigurationEdition_requestAccess$key
}
const RequestAccessConfigurationPopover: FunctionComponent<RequestAccessWorkflowEditionProps> = ({
  data,
}) => {
  const [displayUpdate, setDisplayUpdate] = useState<boolean>(false);
  const handleOpenUpdate = () => setDisplayUpdate(true);
  const handleCloseUpdate = () => setDisplayUpdate(false);
  return (
    <>
      <IconButton
        color="primary"
        aria-label="Workflow"
        aria-haspopup="true"
        onClick={handleOpenUpdate}
        size="large"
      >
        <Edit fontSize="small" />
      </IconButton>

      <RequestAccessConfigurationEdition
        data={data}
        handleClose={handleCloseUpdate}
        open={displayUpdate}
      />
    </>
  );
};

export default RequestAccessConfigurationPopover;
