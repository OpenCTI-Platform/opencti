import React from 'react';
import { useTheme } from '@mui/styles';
import { Theme } from '../components/Theme';
import { State } from '@components/data/connectors/__generated__/ConnectorWorks_data.graphql';
import Tag from '@common/tag/Tag';

interface TaskStatusProps {
  status: State | string;
  label: string;
  variant?: string;
}

const TaskStatus = ({ status, label }: TaskStatusProps) => {
  const theme = useTheme<Theme>();

  const color = () => {
    switch (status) {
      case 'progress':
      case 'provisioning':
      case 'processing':
        return theme.palette.severity.high;
      case 'wait':
        return theme.palette.severity.info;
      case 'complete':
        return theme.palette.severity.low;
      default:
        return theme.palette.severity.info;
    }
  };

  return (
    <>
      <Tag
        color={color()}
        label={label}
      />
    </>
  );
};

export default TaskStatus;
