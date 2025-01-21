import React, { useState } from 'react';
import IconButton from '@mui/material/IconButton';
import { Edit } from '@mui/icons-material';
import RequestAccessDrawer, { requestAccessDrawerQuery } from '@components/settings/sub_types/RequestAccessDrawer';
import { SubTypeWorkflowEditionQuery } from '@components/settings/sub_types/__generated__/SubTypeWorkflowEditionQuery.graphql';
import useQueryLoading from '../../../../utils/hooks/useQueryLoading';

const RequestAccessWorkflowPopover = () => {
  const [displayDrawer, setDisplayDrawer] = useState<boolean>(false);
  const handleOpenDrawer = () => setDisplayDrawer(true);
  const handleCloseDrawer = () => setDisplayDrawer(false);
  const queryRef = useQueryLoading<SubTypeWorkflowEditionQuery>(
    requestAccessDrawerQuery,
    { id: 'Case-Rfi' },
  );
  if (queryRef) {
    return (
      <>
        <IconButton
          color="primary"
          aria-label="Workflow"
          aria-haspopup="true"
          size="large"
          onClick={handleOpenDrawer}
        >
          <Edit fontSize="small"/>
        </IconButton>
        <RequestAccessDrawer
          open={displayDrawer}
          handleClose={handleCloseDrawer}
          queryRef={queryRef}
        />
      </>
    );
  }
  return (
    <div>No query ref</div>
  );
};

export default RequestAccessWorkflowPopover;
