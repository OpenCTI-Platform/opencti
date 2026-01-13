import React, { FunctionComponent } from 'react';
import Chip from '@mui/material/Chip';
import makeStyles from '@mui/styles/makeStyles';
import { useTheme } from '@mui/styles';
import { alpha } from '@mui/material';
import { Theme } from 'src/components/Theme';

// Deprecated - https://mui.com/system/styles/basics/
// Do not use it for new code.
const useStyles = makeStyles(() => ({
  chip: {
    fontSize: 12,
    lineHeight: '12px',
    height: 25,
    marginRight: 7,
    textTransform: 'uppercase',
    borderRadius: 4,
    width: 130,
  },
}));

interface TaskScopeProps {
  label: string;
  scope: string;
}

const TaskScope: FunctionComponent<TaskScopeProps> = ({ label, scope }) => {
  const classes = useStyles();
  const style = classes.chip;
  const theme = useTheme<Theme>();

  const inlineStyles = {
    blue: {
      backgroundColor: alpha(theme.palette.severity?.info || '#4DCCFF', 0.08),
      color: theme.palette.severity?.info || '#4DCCFF',
    },
    grey: {
      backgroundColor: alpha(theme.palette.common.grey || '#95969D', 0.08),
      color: theme.palette.common.grey,
    },
    orange: {
      backgroundColor: alpha(theme.palette.severity?.high || '#E6700F', 0.08),
      color: theme.palette.severity?.high || '#E6700F',
    },
    rose: {
      backgroundColor: alpha('#F8958C', 0.08),
      color: '#F8958C',
    },
    red: {
      backgroundColor: alpha(theme.palette.error.main || '#F14337', 0.08),
      color: theme.palette.error.main,
    },
  };

  switch (scope) {
    case 'SETTINGS':
      return (
        <Chip
          classes={{ root: style }}
          style={inlineStyles.red}
          label={label}
        />
      );
    case 'USER':
      return (
        <Chip
          classes={{ root: style }}
          style={inlineStyles.orange}
          label={label}
        />
      );
    case 'KNOWLEDGE':
      return (
        <Chip
          classes={{ root: style }}
          style={inlineStyles.blue}
          label={label}
        />
      );
    case 'RULE':
      return (
        <Chip
          classes={{ root: style }}
          style={inlineStyles.rose}
          label={label}
        />
      );
    case 'IMPORT':
      return (
        <Chip
          classes={{ root: style }}
          style={inlineStyles.orange}
          label={label}
        />
      );
    case 'PUBLIC_DASHBOARD':
    case 'DASHBOARD':
    case 'INVESTIGATION':
      return (
        <Chip
          classes={{ root: style }}
          style={inlineStyles.orange}
          label={label}
        />
      );
    default:
      return (
        <Chip
          classes={{ root: style }}
          style={inlineStyles.grey}
          label={label}
        />
      );
  }
};

export default TaskScope;
