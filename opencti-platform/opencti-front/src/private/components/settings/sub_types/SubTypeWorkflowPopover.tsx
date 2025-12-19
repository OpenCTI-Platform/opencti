import React, { FunctionComponent, useState } from 'react';
import IconButton from '@common/button/IconButton';
import { Edit } from '@mui/icons-material';
import { InformationOutline } from 'mdi-material-ui';
import { Tooltip } from '@mui/material';
import Loader, { LoaderVariant } from '../../../../components/Loader';
import useQueryLoading from '../../../../utils/hooks/useQueryLoading';
import SubTypeWorkflow, { subTypeWorkflowEditionQuery } from './SubTypeWorkflow';
import { SubTypeWorkflowEditionQuery } from './__generated__/SubTypeWorkflowEditionQuery.graphql';
import { useFormatter } from '../../../../components/i18n';

interface SubTypeStatusPopoverProps {
  subTypeId: string;
  scope: string;
}

const SubTypeStatusPopover: FunctionComponent<SubTypeStatusPopoverProps> = ({ subTypeId, scope }) => {
  const queryRef = useQueryLoading<SubTypeWorkflowEditionQuery>(
    subTypeWorkflowEditionQuery,
    { id: subTypeId },
  );
  const { t_i18n } = useFormatter();
  const [displayUpdate, setDisplayUpdate] = useState<boolean>(false);
  const handleOpenUpdate = () => setDisplayUpdate(true);
  const handleCloseUpdate = () => setDisplayUpdate(false);
  const requestAccessScope = scope === 'REQUEST_ACCESS';
  return (
    <>
      <IconButton
        color="primary"
        aria-label="Workflow"
        onClick={handleOpenUpdate}
        aria-haspopup="true"
      >
        <Edit fontSize="small" />
      </IconButton>
      {requestAccessScope && (
        <Tooltip
          title={t_i18n('RFI of type "request access" are subject to a specific workflow, that you can configure here. Request Access cases have 2 actions, Validate and Decline, that change the status automatically according to your configuration. Only specific groups of users are authorized to validate and decline Request Access cases.')}
        >
          <InformationOutline
            fontSize="small"
            color="primary"
            style={{ cursor: 'default', margin: '-2px 0 -6px 0' }}
          />
        </Tooltip>
      )}
      {queryRef && (
        <React.Suspense
          fallback={<Loader variant={LoaderVariant.inElement} />}
        >
          <SubTypeWorkflow
            scope={scope}
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
