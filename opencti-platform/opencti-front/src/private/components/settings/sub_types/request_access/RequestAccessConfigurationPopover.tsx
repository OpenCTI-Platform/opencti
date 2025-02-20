import { Edit } from '@mui/icons-material';
import IconButton from '@mui/material/IconButton';
import React, { FunctionComponent, useState } from 'react';
import RequestAccessConfigurationEdition, { requestAccessConfigurationEditionQuery } from '@components/settings/sub_types/request_access/RequestAccessConfigurationEdition';
import { RequestAccessConfigurationEditionQuery } from '@components/settings/sub_types/request_access/__generated__/RequestAccessConfigurationEditionQuery.graphql';
import useQueryLoading from '../../../../../utils/hooks/useQueryLoading';
import Loader, { LoaderVariant } from '../../../../../components/Loader';
import { RequestAccessConfigurationEdition_entitySettings$key } from './__generated__/RequestAccessConfigurationEdition_entitySettings.graphql';

interface RequestAccessWorkflowEditionProps {
  id: string
  data: RequestAccessConfigurationEdition_entitySettings$key
}
const RequestAccessConfigurationPopover: FunctionComponent<RequestAccessWorkflowEditionProps> = ({
  id,
  data,
}) => {
  const queryRef = useQueryLoading<RequestAccessConfigurationEditionQuery>(
    requestAccessConfigurationEditionQuery,
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
          <RequestAccessConfigurationEdition
            queryRef={data}
            handleClose={handleCloseUpdate}
            open={displayUpdate}
          />
        </React.Suspense>
      )}

    </>
  );
};

export default RequestAccessConfigurationPopover;
