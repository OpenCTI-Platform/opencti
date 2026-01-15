import React, { FunctionComponent } from 'react';
import makeStyles from '@mui/styles/makeStyles';
import { useTheme } from '@mui/styles';
import type { Theme } from './Theme';
import Tag from '@common/tag/Tag';

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
      backgroundColor: theme.palette.severity?.info,
      color: theme.palette.severity?.info,
    },
    grey: {
      backgroundColor: theme.palette.common.grey,
      color: theme.palette.common.grey,
    },
    orange: {
      backgroundColor: theme.palette.severity?.high,
      color: theme.palette.severity?.high,
    },
    rose: {
      backgroundColor: '#F8958C',
      color: '#F8958C',
    },
    red: {
      backgroundColor: theme.palette.error.main,
      color: theme.palette.error.main,
    },
  };

  switch (scope) {
    case 'SETTINGS':
      return (
        <Tag
          classes={{ root: style }}
          style={inlineStyles.red}
          label={label}
        />
      );
    case 'USER':
      return (
        <Tag
          classes={{ root: style }}
          style={inlineStyles.orange}
          label={label}
        />
      );
    case 'KNOWLEDGE':
      return (
        <Tag
          classes={{ root: style }}
          style={inlineStyles.blue}
          label={label}
        />
      );
    case 'RULE':
      return (
        <Tag
          classes={{ root: style }}
          style={inlineStyles.rose}
          label={label}
        />
      );
    case 'IMPORT':
      return (
        <Tag
          classes={{ root: style }}
          style={inlineStyles.orange}
          label={label}
        />
      );
    case 'PUBLIC_DASHBOARD':
    case 'DASHBOARD':
    case 'INVESTIGATION':
      return (
        <Tag
          classes={{ root: style }}
          style={inlineStyles.orange}
          label={label}
        />
      );
    default:
      return (
        <Tag
          classes={{ root: style }}
          style={inlineStyles.grey}
          label={label}
        />
      );
  }
};

export default TaskScope;
