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
