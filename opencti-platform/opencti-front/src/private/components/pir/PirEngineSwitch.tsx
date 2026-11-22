/*
Copyright (c) 2021-2025 Filigran SAS

This file is part of the OpenCTI Enterprise Edition ("EE") and is
licensed under the OpenCTI Enterprise Edition License (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

https://github.com/OpenCTI-Platform/opencti/blob/master/LICENSE

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
*/

import React, { ReactNode, UIEvent, useState } from 'react';
import { graphql } from 'react-relay';
import { useNavigate } from 'react-router';
import { Dialog, DialogBody, DialogContent, DialogDescription, DialogFooter, DialogTitle, Text } from '@filigran/design-system';
import Button from '@common/button/Button';
import { useFormatter } from '../../../components/i18n';
import useApiMutation from '../../../utils/hooks/useApiMutation';
import { MESSAGING$ } from '../../../relay/environment';
import stopEvent from '../../../utils/domEvent';
import { PirEngineSwitchMutation } from './__generated__/PirEngineSwitchMutation.graphql';

// Moves a PIR onto the intelligence requirement engine. The backend checks that the requirement
// writes back the same scores and explanations as the legacy engine before switching; on any
// mismatch nothing is written and the PIR stays on the legacy engine.

const pirEngineSwitchMutation = graphql`
  mutation PirEngineSwitchMutation($id: ID!, $engine: PirEngine!) {
    pirEngineSwitch(id: $id, engine: $engine) {
      switched
      engine
      requirement_id
      flags
      reason
      mismatches {
        entity_id
      }
    }
  }
`;

export const requirementPath = (requirementId: string) => `/dashboard/intelligence_requirements/${requirementId}`;

interface ChildrenProps {
  handleOpen: (e?: UIEvent) => void;
  switching: boolean;
}

interface PirEngineSwitchProps {
  pirId: string;
  pirName: string;
  onClose?: () => void;
  children: (props: ChildrenProps) => ReactNode;
}

const PirEngineSwitch = ({ pirId, pirName, onClose, children }: PirEngineSwitchProps) => {
  const { t_i18n } = useFormatter();
  const navigate = useNavigate();
  const [open, setOpen] = useState(false);
  const [commit, switching] = useApiMutation<PirEngineSwitchMutation>(pirEngineSwitchMutation);

  const handleOpen = (e?: UIEvent) => {
    if (e) stopEvent(e);
    setOpen(true);
  };
  const handleClose = () => {
    if (switching) return;
    setOpen(false);
    onClose?.();
  };

  const confirm = () => {
    commit({
      variables: { id: pirId, engine: 'requirement' },
      onCompleted: (response) => {
        const result = response.pirEngineSwitch;
        setOpen(false);
        onClose?.();
        if (result?.switched && result.requirement_id) {
          MESSAGING$.notifySuccess(t_i18n('The PIR now runs on the intelligence requirement engine'));
          navigate(requirementPath(result.requirement_id));
          return;
        }
        MESSAGING$.notifyError((result?.mismatches?.length ?? 0) > 0
          ? t_i18n('The PIR was not switched: its flags would change. It stays on the current engine.')
          : t_i18n('The PIR was not switched: {reason}', { values: { reason: result?.reason ?? '' } }));
      },
      onError: () => setOpen(false),
    });
  };

  return (
    <>
      {children({ handleOpen, switching })}
      <Dialog
        open={open}
        onOpenChange={(isOpen) => {
          if (!isOpen) handleClose();
        }}
      >
        <DialogContent size="sm">
          <DialogTitle>
            <Text as="span" variant="title-md">{t_i18n('Switch to the intelligence requirement engine')}</Text>
          </DialogTitle>
          <DialogBody>
            <div className="flex flex-col gap-2">
              <DialogDescription>
                {t_i18n('{name} will be scored by its intelligence requirement: inbox with proof paths, score history, editable criteria with rescan.', { values: { name: pirName } })}
              </DialogDescription>
              <Text variant="content-base">
                {t_i18n('Its current flags and scores are checked first and kept unchanged; if any would change, nothing is switched. The API, connectors and playbooks keep working as before.')}
              </Text>
            </div>
          </DialogBody>
          <DialogFooter>
            <Button variant="secondary" onClick={handleClose} disabled={switching}>{t_i18n('Cancel')}</Button>
            <Button onClick={confirm} disabled={switching}>{t_i18n('Switch')}</Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>
    </>
  );
};

export default PirEngineSwitch;
