import React, { SyntheticEvent } from 'react';
import Chip from '@mui/material/Chip';
import Tooltip from '@mui/material/Tooltip';
import { useTheme } from '@mui/material/styles';
import makeStyles from '@mui/styles/makeStyles';
import { useFormatter } from '../../../../components/i18n';
import { hexToRGB } from '../../../../utils/Colors';
import { truncate } from '../../../../utils/String';
import { HandleAddFilter } from '../../../../utils/hooks/useLocalStorage';

const useStyles = makeStyles(() => ({
  label: {
    height: 25,
    fontSize: 12,
    margin: '0 7px 7px 0',
    borderRadius: 4,
  },
  labelInList: {
    fontSize: 12,
    height: 20,
    float: 'left',
    margin: '0 7px 0 0',
    borderRadius: 4,
  },
  labelInSearch: {
    height: 25,
    fontSize: 12,
    margin: '0 7px 0 0',
    borderRadius: 4,
  },
}));

interface StixCoreObjectLabelsProps {
  labels: readonly {
    readonly color: string | null | undefined,
    readonly id: string,
    readonly value: string | null | undefined,
  }[] | null | undefined,
  onClick?: HandleAddFilter,
  variant?: string,
  revoked?: boolean,
}

const StixCoreObjectLabels = ({
  labels,
  onClick,
  variant,
  revoked,
}: StixCoreObjectLabelsProps) => {
  const { t_i18n } = useFormatter();
  const theme = useTheme();
  const classes = useStyles();
  let style = classes.label;
  if (variant === 'inList') {
    style = classes.labelInList;
  }
  if (variant === 'inSearch') {
    style = classes.labelInSearch;
  }

  if (!revoked && labels && labels.length > 0) {
    return (
      <>
        {
          labels.slice(0, 3).map(
            (label) => (
              <Tooltip key={label.id} title={label.value}>
                <Chip
                  variant="outlined"
                  classes={{ root: style }}
                  label={truncate(label.value, 25)}
                  style={{
                    color: label.color ?? undefined,
                    borderColor: label.color ?? undefined,
                    backgroundColor: hexToRGB(label.color),
                    cursor: onClick ? 'pointer' : 'inherit',
                  }}
                  onClick={(e: SyntheticEvent) => {
                    e.preventDefault();
                    e.stopPropagation();
                    onClick?.('objectLabel', label.id, 'eq');
                  }}
                />
              </Tooltip>
            ),
          )
        }
      </>
    );
  }

  return <>
    {revoked ? (
      <Chip
        classes={{ root: style }}
        variant="outlined"
        label={t_i18n('Revoked')}
        style={{
          color: '#d32f2f',
          borderColor: '#d32f2f',
          backgroundColor: 'rgba(211, 47, 47, .1)',
        }}
        onClick={(e: SyntheticEvent) => {
          e.preventDefault();
          e.stopPropagation();
          onClick?.('objectLabel', null, 'eq');
        }}
      />
    ) : (
      <Chip
        classes={{ root: style }}
        variant="outlined"
        label={t_i18n('No label')}
        style={{
          color: theme.palette.mode === 'dark' ? '#ffffff' : '#000000',
          borderColor:
            theme.palette.mode === 'dark' ? '#ffffff' : '#000000',
          backgroundColor: hexToRGB(
            theme.palette.mode === 'dark' ? '#ffffff' : 'transparent',
          ),
        }}
        onClick={(e: SyntheticEvent) => {
          e.preventDefault();
          e.stopPropagation();
          onClick?.('objectLabel', null, 'eq');
        }}
      />
    )}
  </>;
};

export default StixCoreObjectLabels;
