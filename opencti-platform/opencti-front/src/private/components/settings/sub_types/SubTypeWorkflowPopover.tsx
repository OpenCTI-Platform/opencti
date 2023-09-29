import React, { useState } from 'react';
import IconButton from '@mui/material/IconButton';
import { Edit } from '@mui/icons-material';
import Loader, { LoaderVariant } from '../../../../components/Loader';
import useQueryLoading from '../../../../utils/hooks/useQueryLoading';
import SubTypeWorkflow, { subTypeWorkflowEditionQuery } from './SubTypeWorkflow';
import { SubTypeWorkflowEditionQuery } from './__generated__/SubTypeWorkflowEditionQuery.graphql';

const SubTypeStatusPopover = ({ subTypeId }: { subTypeId: string }) => {
  const queryRef = useQueryLoading<SubTypeWorkflowEditionQuery>(
    subTypeWorkflowEditionQuery,
    { id: subTypeId },
  );
  const [displayUpdate, setDisplayUpdate] = useState<boolean>(false);
  const handleOpenUpdate = () => setDisplayUpdate(true);
  const handleCloseUpdate = () => setDisplayUpdate(false);
  return (
    <>
      <IconButton
        color="secondary"
        aria-label="Workflow"
        onClick={handleOpenUpdate}
        aria-haspopup="true"
        size="large"
      >
        <Edit fontSize="small" />
      </IconButton>
      {queryRef && (
        <React.Suspense
          fallback={<Loader variant={LoaderVariant.inElement} />}
        >
          <SubTypeWorkflow
            queryRef={queryRef}
            handleClose={handleCloseUpdate}
            open={displayUpdate}
          />
        </React.Suspense>
      )}
    </>
  );
};

export default SubTypeStatusPopover;
