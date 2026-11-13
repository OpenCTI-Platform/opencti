import React, { FunctionComponent, useState } from 'react';
import Button from '@common/button/Button';
import { useFormatter } from '../../../../../components/i18n';
import AlertLiveCreation from './AlertLiveCreation';
import { AlertingPaginationQuery$variables } from './__generated__/AlertingPaginationQuery.graphql';
import { AlertLiveCreationActivityMutation$data } from './__generated__/AlertLiveCreationActivityMutation.graphql';
import AlertDigestCreation from './AlertDigestCreation';

interface TriggerCreationProps {
  contextual?: boolean;
  hideSpeedDial?: boolean;
  open?: boolean;
  handleClose?: () => void;
  inputValue?: string;
  paginationOptions?: AlertingPaginationQuery$variables;
  creationCallback?: (data: AlertLiveCreationActivityMutation$data) => void;
}

const AlertCreation: FunctionComponent<TriggerCreationProps> = ({
  contextual,
  inputValue,
  paginationOptions,
  creationCallback,
  handleClose,
  open,
}) => {
  const { t_i18n } = useFormatter();
  // Live
  const [openLive, setOpenLive] = useState(false);
  const handleOpenCreateLive = () => {
    setOpenLive(true);
  };
  // Digest
  const [openDigest, setOpenDigest] = useState(false);
  const handleOpenCreateDigest = () => {
    setOpenDigest(true);
  };
  return (
    <>
      <Button
        onClick={handleOpenCreateDigest}
      >
        {t_i18n('Create {entity_type}', {
          values: { entity_type: t_i18n('Regular digest') },
        })}
      </Button>
      <Button
        onClick={handleOpenCreateLive}
      >
        {t_i18n('Create {entity_type}', {
          values: { entity_type: t_i18n('Live trigger') },
        })}
      </Button>
      <AlertLiveCreation
        contextual={contextual}
        inputValue={inputValue}
        paginationOptions={paginationOptions}
        open={open ?? openLive}
        handleClose={() => {
          if (handleClose) {
            handleClose();
          } else {
            setOpenLive(false);
          }
        }}
        creationCallback={creationCallback}
      />
      <AlertDigestCreation
        contextual={contextual}
        inputValue={inputValue}
        paginationOptions={paginationOptions}
        open={openDigest}
        handleClose={() => setOpenDigest(false)}
      />
    </>
  );
};

export default AlertCreation;
