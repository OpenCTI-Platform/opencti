import React from 'react';
import makeStyles from '@mui/styles/makeStyles';
import Chip from '@mui/material/Chip';
import { alpha } from '@mui/material';
import { useTheme } from '@mui/styles';
import { Theme } from '../components/Theme';
import { State } from '@components/data/connectors/__generated__/ConnectorWorks_data.graphql';

const useStyles = makeStyles<Theme>(() => ({
  chip: {
    fontSize: 12,
    lineHeight: '12px',
    height: 25,
    marginRight: 7,
    textTransform: 'uppercase',
    borderRadius: 4,
    width: 130,
  },
  chipInList: {
    fontSize: 12,
    lineHeight: '12px',
    height: 20,
    float: 'left',
    textTransform: 'uppercase',
    borderRadius: 4,
    width: 130,
  },
}));

interface TaskStatusProps {
  status: State | string;
  label: string;
  variant?: string;
}

const TaskStatus = ({ status, label, variant }: TaskStatusProps) => {
  const classes = useStyles();
  const style = variant === 'inList' ? classes.chipInList : classes.chip;
  const theme = useTheme<Theme>();
  const inlineStyles = {
    white: {
      backgroundColor: theme.palette.common.white,
      color: theme.palette.common.grey,
    },
    green: {
      backgroundColor: alpha(theme.palette.success.main || '#17AB1F', 0.08),
      color: theme.palette.success.main,
    },
    blue: {
      backgroundColor: alpha(theme.palette.severity.info, 0.08),
      color: theme.palette.severity.info,
    },
    grey: {
      backgroundColor: alpha(theme.palette.common.grey || '#95969D', 0.08),
      color: theme.palette.common.grey,
    },
    orange: {
      backgroundColor: alpha(theme.palette.severity.high, 0.08),
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
    <Chip
      classes={{ root: style }}
      style={inlineStyle()}
      label={label}
    />
  );
};

export default TaskStatus;
