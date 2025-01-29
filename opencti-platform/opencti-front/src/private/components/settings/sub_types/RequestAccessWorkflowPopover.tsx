import { Edit } from '@mui/icons-material';
import IconButton from '@mui/material/IconButton';
import React, { FunctionComponent, useState } from 'react';
import RequestAccessWorkflow, { requestAccessWorkflowEditionQuery } from '@components/settings/sub_types/RequestAccessWorkflow';
import { RequestAccessWorkflowEditionQuery } from '@components/settings/sub_types/__generated__/RequestAccessWorkflowEditionQuery.graphql';
import { RequestAccessStatusFragment_entitySetting$key } from '@components/settings/sub_types/__generated__/RequestAccessStatusFragment_entitySetting.graphql';
import useQueryLoading from '../../../../utils/hooks/useQueryLoading';
import Loader, { LoaderVariant } from '../../../../components/Loader';

interface RequestAccessWorkflowEditionProps {
  id: string
  data: RequestAccessStatusFragment_entitySetting$key
}
const RequestAccessWorkflowEdition: FunctionComponent<RequestAccessWorkflowEditionProps> = ({
  id,
  data,
}) => {
  const queryRef = useQueryLoading<RequestAccessWorkflowEditionQuery>(
    requestAccessWorkflowEditionQuery,
    { id },
  );
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
      {queryRef && (
        <React.Suspense
          fallback={<Loader variant={LoaderVariant.inElement} /> }
        >
          <RequestAccessWorkflow
            queryRef={data}
            handleClose={handleCloseUpdate}
            open={displayUpdate}
            workflowId={id}
          />
        </React.Suspense>
      )}

    </>
  );
};

export default RequestAccessWorkflowEdition;
