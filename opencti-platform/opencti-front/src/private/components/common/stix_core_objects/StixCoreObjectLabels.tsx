import { Chip, Tooltip, useTheme } from '@mui/material';
import React from 'react';
import { truncate } from '../../../../utils/String';
import { useFormatter } from '../../../../components/i18n';
import useAuth from '../../../../utils/hooks/useAuth';
import { hexToRGB } from '../../../../utils/Colors';
import type { Theme } from '../../../../components/Theme';

type Label = {
  id: string,
  value?: string | null,
  color?: string | null,
};

/* eslint-disable  @typescript-eslint/no-explicit-any */
interface StixCoreObjectLabelsProps {
  labels?: Label[] | readonly Label[] | null,
  onClick?: (
    k: string,
    id: string,
    op?: any,
    event?: any,
  ) => void,
  variant?: string,
  revoked?: boolean,
}

const StixCoreObjectLabels: React.FC<StixCoreObjectLabelsProps> = ({
  labels,
  onClick,
  variant,
  revoked,
}) => {
  const { t_i18n } = useFormatter();
  const { me: { monochrome_labels } } = useAuth();
  const { palette: { mode } } = useTheme();
  const theme = useTheme<Theme>();
  const normalBackground = mode === 'dark' ? 'transparent' : '#ffffff';
  const hasLabels = !revoked && labels && labels.length > 0;
  let style = {};
  switch (variant) {
    case 'inList':
      style = {
        fontSize: 12,
        height: 20,
        float: 'left',
        margin: '0 7px 0 0',
        borderRadius: 4,
      };
      break;
    case 'inSearch':
      style = {
        height: 25,
        fontSize: 12,
        margin: '0 7px 0 0',
        borderRadius: 4,
      };
      break;
    default:
      style = {
        height: 25,
        fontSize: 12,
        margin: '0 7px 7px 0',
        borderRadius: 4,
      };
  }

  if (hasLabels) {
    return labels.slice(0, 3).map((label) => (
      <Tooltip key={label.id} title={label.value}>
        <Chip
          variant={monochrome_labels ? 'filled' : 'outlined'}
          label={truncate(label.value, 25)}
          style={{
            ...style,
            color: theme.palette.chip.main,
            borderColor: monochrome_labels ? undefined : label.color ?? undefined,
            backgroundColor: monochrome_labels ? theme.palette.background.accent : hexToRGB(label.color),
          }}
          onClick={typeof onClick === 'function'
            ? () => onClick('objectLabel', label.id, 'eq')
            : undefined
          }
        />
      </Tooltip>
    ));
  } if (revoked) {
    return (
      <Chip
        variant={monochrome_labels ? 'filled' : 'outlined'}
        label={t_i18n('Revoked')}
        style={{
          ...style,
          color: monochrome_labels ? theme.palette.chip.main : '#d32f2f',
          borderColor: monochrome_labels ? undefined : '#d32f2f',
          backgroundColor: monochrome_labels ? theme.palette.background.accent : 'rgba(211, 47, 47, .1)',
        }}
        onClick={typeof onClick === 'function'
          ? () => onClick('objectLabel', '', 'eq')
          : undefined
        }
      />
    );
  }
  return (
    <Chip
      variant={monochrome_labels ? 'filled' : 'outlined'}
      label={t_i18n('No label')}
      style={{
        ...style,
        color: theme.palette.chip.main,
        borderColor: monochrome_labels ? undefined : theme.palette.chip.main,
        backgroundColor: monochrome_labels ? theme.palette.background.accent : normalBackground,
      }}
      onClick={typeof onClick === 'function'
        ? () => onClick('objectLabel', '', 'eq')
        : undefined
        }
    />
  );
};

export default StixCoreObjectLabels;
