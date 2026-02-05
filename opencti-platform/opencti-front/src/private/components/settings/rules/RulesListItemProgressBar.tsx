import React from 'react';
import LinearProgress from '@mui/material/LinearProgress';
import { Work } from './RulesList';
import { useFormatter } from '../../../../components/i18n';
import Label from '../../../../components/common/label/Label';
import { Stack } from '@mui/material';

interface RuleListItemProgressBarProps {
  taskEnable: boolean;
  work: NonNullable<Work>;
}

const RuleListItemProgressBar = ({ taskEnable, work }: RuleListItemProgressBarProps) => {
  const { t_i18n } = useFormatter();
  const { tracking, status } = work;

  const expectedNumber = tracking?.import_expected_number ?? 1;
  const processedNumber = tracking?.import_processed_number ?? 0;
  const workCompleted = status === 'complete';
  const labelEnableComplete = t_i18n('This rule has been applied on the existing data');
  const labelEnableOngoing = t_i18n('Applying this rule on the existing data');
  const labelDisableComplete = t_i18n('Rule has been cleaned up on the existing data');
  const labelDisableOngoing = t_i18n('Cleaning up this rule on the existing data');

  const percentProcessed = Math.round(((processedNumber) / (expectedNumber)) * 100);
  let progressValue = 100;
  if (!workCompleted) {
    if (expectedNumber === 0) progressValue = 0;
    else progressValue = percentProcessed;
  }

  const getLabel = () => {
    if (taskEnable && workCompleted) return labelEnableComplete;
    if (taskEnable) return labelEnableOngoing;
    if (workCompleted) return labelDisableComplete;
    return labelDisableOngoing;
  };

  return (
    <div>
      <Stack gap={1}>
        <Label>
          {getLabel()}
        </Label>
        <LinearProgress
          style={{ borderRadius: 4, height: 10 }}
          variant="determinate"
          value={progressValue}
        />
      </Stack>
    </div>
  );
};

export default RuleListItemProgressBar;
