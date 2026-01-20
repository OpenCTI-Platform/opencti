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

  switch (scope) {
    case 'SETTINGS':
      return (
        <Tag
          color={theme.palette.designSystem.tertiary.red[400]}
          label={label}
        />
      );
    case 'USER':
      return (
        <Tag
          color={theme.palette.designSystem.tertiary.orange[400]}
          label={label}
        />
      );
    case 'KNOWLEDGE':
      return (
        <Tag
          color={theme.palette.designSystem.tertiary.darkBlue[300]}
          label={label}
        />
      );
    case 'RULE':
      return (
        <Tag
          color={theme.palette.designSystem.tertiary.red[100]}
          label={label}
        />
      );
    case 'IMPORT':
      return (
        <Tag
          color={theme.palette.designSystem.tertiary.orange[400]}
          label={label}
        />
      );
    case 'PUBLIC_DASHBOARD':
    case 'DASHBOARD':
    case 'INVESTIGATION':
      return (
        <Tag
          color={theme.palette.designSystem.tertiary.orange[400]}
          label={label}
        />
      );
    default:
      return (
        <Tag
          color={theme.palette.designSystem.tertiary.grey[400]}
          label={label}
        />
      );
  }
};

export default TaskScope;
