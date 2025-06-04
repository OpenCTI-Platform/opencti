import React from 'react';
import LinearProgress from '@mui/material/LinearProgress';
import { Work } from './RulesList';
import { useFormatter } from '../../../../components/i18n';

interface RuleListItemProgressBarProps {
  taskEnable: boolean
  work: NonNullable<Work>
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

  return (
    <div
      style={{
        width: '100%',
        textAlign: 'center',
        fontSize: 9,
        fontFamily: 'Consolas, monaco, monospace',
      }}
    >
      {taskEnable && workCompleted && labelEnableComplete}
      {taskEnable && !workCompleted && labelEnableOngoing}
      {!taskEnable && workCompleted && labelDisableComplete}
      {!taskEnable && !workCompleted && labelDisableOngoing}

      <LinearProgress
        style={{ borderRadius: 4, height: 10 }}
        variant="determinate"
        value={progressValue}
      />
    </div>
  );
};

export default RuleListItemProgressBar;
