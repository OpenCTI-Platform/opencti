import React from 'react';
import LinearProgress from '@mui/material/LinearProgress';
import { Task } from './RulesList';
import { useFormatter } from '../../../../components/i18n';

interface RuleListItemProgressBarProps {
  task: NonNullable<Task>
}

const RuleListItemProgressBar = ({ task }: RuleListItemProgressBarProps) => {
  const { t_i18n } = useFormatter();
  const { enable, completed, task_expected_number, task_processed_number } = task;

  const labelEnableComplete = t_i18n('This rule has been applied on the existing data');
  const labelEnableOngoing = t_i18n('Applying this rule on the existing data');
  const labelDisableComplete = t_i18n('Rule has been cleaned up on the existing data');
  const labelDisableOngoing = t_i18n('Cleaning up this rule on the existing data');

  const percentProcessed = Math.round(
    ((task_processed_number ?? 0) / (task_expected_number ?? 1)) * 100,
  );
  let progressValue = 100;
  if (!completed) {
    if (task_expected_number === 0) progressValue = 0;
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
      {enable && completed && labelEnableComplete}
      {enable && !completed && labelEnableOngoing}
      {!enable && completed && labelDisableComplete}
      {!enable && !completed && labelDisableOngoing}

      <LinearProgress
        style={{ borderRadius: 4, height: 10 }}
        variant="determinate"
        value={progressValue}
      />
    </div>
  );
};

export default RuleListItemProgressBar;
