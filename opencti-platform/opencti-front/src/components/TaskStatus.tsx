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
  const inlineStyles = {
    white: {
      backgroundColor: theme.palette.common.white,
      color: theme.palette.common.grey,
    },
    green: {
      color: theme.palette.severity.low,
    },
    blue: {
      color: theme.palette.severity.info,
    },
    grey: {
      color: theme.palette.severity.none,
    },
    orange: {
      color: theme.palette.severity.high,
    },
  };

  const inlineStyle = () => {
    switch (status) {
      case 'progress':
      case 'provisioning':
      case 'processing':
        return inlineStyles.orange;
      case 'wait':
        return inlineStyles.blue;
      case 'complete':
        return inlineStyles.green;
      default:
        return inlineStyles.blue;
    }
  };

  return (
    <Tag
      style={inlineStyle()}
      label={label}
    />
  );
};

export default TaskStatus;
