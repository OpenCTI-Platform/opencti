import React from 'react';
import { useTheme } from '@mui/styles';
import type { Theme } from '../../../../components/Theme';
import { useFormatter } from '../../../../components/i18n';
import { Tooltip } from '@components';

const DangerZoneChip = ({ style }: { style?: React.CSSProperties }) => {
  const { t_i18n } = useFormatter();
  const theme = useTheme<Theme>();
  return (
    <div
      style={{
        fontSize: 'xx-small',
        textTransform: 'uppercase',
        fontWeight: 500,
        height: 14,
        display: 'inline-flex',
        justifyContent: 'center',
        alignItems: 'center',
        marginTop: theme.spacing(0.25),
        marginLeft: theme.spacing(0.5),
        padding: `${theme.spacing(1)} ${theme.spacing(0.5)}`,
        borderRadius: theme.borderRadius,
        border: `1px solid ${theme.palette.dangerZone.main}`,
        color: theme.palette.dangerZone.text?.primary,
        backgroundColor: 'transparent',
        ...style,
      }}
    >
      <Tooltip
        title={t_i18n('DangerZoneTooltip')}
      >
        <>
          Danger Zone
        </>
      </Tooltip>
    </div>
  );
};

export default DangerZoneChip;
