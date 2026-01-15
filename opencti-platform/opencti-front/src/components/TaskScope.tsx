import React, { FunctionComponent } from 'react';
import { useTheme } from '@mui/styles';
import type { Theme } from './Theme';
import Tag from '@common/tag/Tag';

interface TaskScopeProps {
  label: string;
  scope: string;
}

const TaskScope: FunctionComponent<TaskScopeProps> = ({ label, scope }) => {
  const theme = useTheme<Theme>();

  const inlineStyles = {
    blue: {
      backgroundColor: theme.palette.tertiary.darkBlue[300],
      color: theme.palette.tertiary.darkBlue[300],
    },
    grey: {
      backgroundColor: theme.palette.tertiary.grey[400],
      color: theme.palette.tertiary.grey[400],
    },
    orange: {
      backgroundColor: theme.palette.tertiary.orange[400],
      color: theme.palette.tertiary.orange[400],
    },
    rose: {
      backgroundColor: theme.palette.tertiary.red[100],
      color: theme.palette.tertiary.red[100],
    },
    red: {
      backgroundColor: theme.palette.tertiary.red[400],
      color: theme.palette.tertiary.red[400],
    },
  };

  switch (scope) {
    case 'SETTINGS':
      return (
        <Tag
          style={inlineStyles.red}
          label={label}
        />
      );
    case 'USER':
      return (
        <Tag
          style={inlineStyles.orange}
          label={label}
        />
      );
    case 'KNOWLEDGE':
      return (
        <Tag
          style={inlineStyles.blue}
          label={label}
        />
      );
    case 'RULE':
      return (
        <Tag
          style={inlineStyles.rose}
          label={label}
        />
      );
    case 'IMPORT':
      return (
        <Tag
          style={inlineStyles.orange}
          label={label}
        />
      );
    case 'PUBLIC_DASHBOARD':
    case 'DASHBOARD':
    case 'INVESTIGATION':
      return (
        <Tag
          style={inlineStyles.orange}
          label={label}
        />
      );
    default:
      return (
        <Tag
          style={inlineStyles.grey}
          label={label}
        />
      );
  }
};

export default TaskScope;
