import React, { FunctionComponent, Suspense, useState } from 'react';
import Button from '@common/button/Button';
import { useFormatter } from '../../../../components/i18n';
import { TriggersLinesPaginationQuery$variables } from './__generated__/TriggersLinesPaginationQuery.graphql';
import TriggerDigestCreation from './TriggerDigestCreation';
import TriggerLiveCreation from './TriggerLiveCreation';
import TriggerChangeDigestCreation from './TriggerChangeDigestCreation';
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
  // Change digest
  const [openChangeDigest, setOpenChangeDigest] = useState(false);
  return (
    <>
      {!contextual && (
        <Button onClick={() => setOpenChangeDigest(true)} data-testid="change-digest-create">
          {t_i18n('Create {entity_type}', {
            values: { entity_type: t_i18n('Change digest') },
          })}
        </Button>
      )}
      {/* No marginRight: the row that holds these two buttons is a flex container with `gap: 8`, so an 8px margin
          on top of it made the pair 16px apart -- the "trop éloignés" in the pass. */}
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
      {!contextual && openChangeDigest && (
        <Suspense fallback={null}>
          <TriggerChangeDigestCreation
            paginationOptions={paginationOptions}
            open={openChangeDigest}
            handleClose={() => setOpenChangeDigest(false)}
          />
        </Suspense>
      )}
    </>
  );
};

export default TriggerCreation;
