import React, { FunctionComponent, useState } from 'react';
import Button from '@common/button/Button';
import { useFormatter } from '../../../../components/i18n';
import { TriggersLinesPaginationQuery$variables } from './__generated__/TriggersLinesPaginationQuery.graphql';
import TriggerDigestCreation from './TriggerDigestCreation';
import TriggerLiveCreation from './TriggerLiveCreation';
import { TriggerLiveCreationKnowledgeMutation$data } from './__generated__/TriggerLiveCreationKnowledgeMutation.graphql';

interface TriggerCreationProps {
  contextual?: boolean;
  hideSpeedDial?: boolean;
  open?: boolean;
  handleClose?: () => void;
  inputValue?: string;
  paginationOptions?: TriggersLinesPaginationQuery$variables;
  creationCallback?: (data: TriggerLiveCreationKnowledgeMutation$data) => void;
}

const TriggerCreation: FunctionComponent<TriggerCreationProps> = ({
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
      {/* No marginRight: the row that holds these two buttons is a flex
          container with `gap: 8`, so an 8px margin on top of it made the pair
          16px apart -- the "trop éloignés" in the pass. The gap is the row's
          to own. */}
      <Button
        onClick={handleOpenCreateDigest}
      >
        {t_i18n('', {
          id: 'Create ...',
          values: { entity_type: t_i18n('Regular digest') },
        })}
      </Button>
      <Button
        onClick={handleOpenCreateLive}
      >
        {t_i18n('', {
          id: 'Create ...',
          values: { entity_type: t_i18n('Live trigger') },
        })}
      </Button>
      <TriggerLiveCreation
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
      <TriggerDigestCreation
        contextual={contextual}
        inputValue={inputValue}
        paginationOptions={paginationOptions}
        open={openDigest}
        handleClose={() => setOpenDigest(false)}
      />
    </>
  );
};

export default TriggerCreation;
