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

import { useEffect, useMemo, useState } from 'react';
import { useReactFlow } from 'reactflow';
import { Radio, RadioGroup } from '@filigran/design-system';
import Button from '@common/button/Button';
import Dialog from '@common/dialog/Dialog';
import DialogActions from '@mui/material/DialogActions';
import DialogContentText from '@mui/material/DialogContentText';
import { useFormatter } from '../../../../../components/i18n';
import type { PlaybookAction, PlaybookNode, SetPlaybookAction, SetSelectedPlaybookNode } from '../types/playbook-types';
import { countDescendantSteps, type PlaybookDeleteChoice, playbookDeleteOptions } from '../utils/playbookDeleteChoices';

interface PlaybookFlowDeleteNodeProps {
  action: PlaybookAction | null;
  setAction: SetPlaybookAction;
  selectedNode: PlaybookNode | null;
  setSelectedNode: SetSelectedPlaybookNode;
  // keepChildren: delete this step only and link its children to its parents.
  deleteNode: (keepChildren: boolean) => void;
}

const PlaybookFlowDeleteNode = ({
  action,
  setAction,
  selectedNode,
  setSelectedNode,
  deleteNode,
}: PlaybookFlowDeleteNodeProps) => {
  const { t_i18n } = useFormatter();
  const { getEdges, getNode } = useReactFlow();
  const open = selectedNode !== null && action === 'delete';
  const options = useMemo(() => {
    if (!open || !selectedNode) return playbookDeleteOptions(0, false);
    const descendants = countDescendantSteps(selectedNode.id, getEdges(), (id) => getNode(id)?.type === 'workflow');
    return playbookDeleteOptions(descendants, Boolean(selectedNode.data.component?.is_entry_point));
  }, [open, selectedNode?.id]);
  const [choice, setChoice] = useState<PlaybookDeleteChoice>(options.defaultChoice);
  useEffect(() => setChoice(options.defaultChoice), [options.defaultChoice, selectedNode?.id]);
  const close = () => {
    setSelectedNode(null);
    setAction(null);
  };
  const branchLabel = t_i18n('{count, plural, one {Delete this step and the step after it} other {Delete this step and the # steps after it}}', {
    values: { count: options.descendants },
  });

  return (
    <Dialog open={open} onClose={close} title={t_i18n('Are you sure?')}>
      {options.descendants === 0 && (
        <DialogContentText>{t_i18n('Do you want to delete this node?')}</DialogContentText>
      )}
      {options.descendants > 0 && options.choices.length === 1 && (
        <DialogContentText data-testid="playbook-delete-entry-point">
          {t_i18n('{count, plural, one {Deleting the entry point also deletes the step after it.} other {Deleting the entry point also deletes the # steps after it.}}', {
            values: { count: options.descendants },
          })}
        </DialogContentText>
      )}
      {options.choices.length > 1 && (
        <RadioGroup
          aria-label={t_i18n('What to delete')}
          name="playbook-delete-choice"
          value={choice}
          onValueChange={(value) => setChoice(value as PlaybookDeleteChoice)}
        >
          <Radio value="step" label={t_i18n('Delete this step only')} />
          <Radio value="branch" label={branchLabel} />
        </RadioGroup>
      )}
      <DialogActions>
        <Button variant="secondary" onClick={close}>
          {t_i18n('Cancel')}
        </Button>
        <Button onClick={() => deleteNode(options.choices.length > 1 ? choice === 'step' : false)}>
          {t_i18n('Confirm')}
        </Button>
      </DialogActions>
    </Dialog>
  );
};

export default PlaybookFlowDeleteNode;
