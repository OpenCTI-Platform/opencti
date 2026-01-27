import React, { ReactElement } from 'react';
import Tooltip from '@mui/material/Tooltip';
import CircularProgress from '@mui/material/CircularProgress';
import { useTheme } from '@mui/styles';
import { useFormatter } from './i18n';
import Tag from '@common/tag/Tag';
import type { Theme } from './Theme';

type ItemBooleanProps = {
  status: string | boolean | null | undefined;
  label?: string | ReactElement;
  neutralLabel?: string | null | undefined;
  reverse?: boolean;
  labelTextTransform?: 'capitalize' | 'uppercase' | 'lowercase' | 'none';
  tooltip?: string;
};

const ItemBoolean = ({
  label,
  neutralLabel,
  status,
  reverse = false,
  labelTextTransform,
  tooltip,
}: ItemBooleanProps) => {
  const theme = useTheme<Theme>();
  const { t_i18n } = useFormatter();

  const renderTag = () => {
    if (status === true) {
      return (
        <Tag
          label={label}
          color={reverse ? theme.palette.error.main : theme.palette.success.main}
          labelTextTransform={labelTextTransform}
        />
      );
    }

    if (status === null) {
      return (
        <Tag
          label={neutralLabel || t_i18n('Not applicable')}
          labelTextTransform={labelTextTransform}
        />
      );
    }

    if (status === 'ee') {
      return (
        <Tag
          label={neutralLabel || t_i18n('EE')}
          color={theme.palette.ee.lightBackground}
          labelTextTransform={labelTextTransform}
        />
      );
    }

    if (status === undefined) {
      return (
        <Tag
          label={(
            <CircularProgress
              size={10}
              color="primary"
            />
          )}
        />
      );
    }

    return (
      <Tag
        label={label}
        color={reverse ? theme.palette.success.main : theme.palette.error.main}
      />
    );
  };

  if (tooltip) {
    return (
      <Tooltip
        title={tooltip}
        slotProps={
          labelTextTransform
            ? {
                tooltip: {
                  sx: {
                    textTransform: labelTextTransform,
                    '&::first-letter': {
                      textTransform: labelTextTransform,
                    },
                  },
                },
              }
            : undefined
        }
      >
        {renderTag()}
      </Tooltip>
    );
  }
  return renderTag();
};

export default ItemBoolean;
