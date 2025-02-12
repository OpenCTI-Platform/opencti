import { useTheme } from '@mui/styles';
import Typography from '@mui/material/Typography';
import React, { FunctionComponent, ReactElement, ReactNode } from 'react';
import DangerZoneChip from '@components/common/danger_zone/DangerZoneChip';
import type { Theme } from '../../../../components/Theme';
import { hexToRGB } from '../../../../utils/Colors';
import { useFormatter } from '../../../../components/i18n';
import useSensitiveModifications, { SensitiveConfigType } from '../../../../utils/hooks/useSensitiveModifications';

interface DangerZoneBlockProps {
  title?: ReactNode
  component?: ((props: { disabled?: boolean, style?: React.CSSProperties }) => ReactElement) | ReactNode
  children?: ((props: { disabled?: boolean, style?: React.CSSProperties }) => ReactElement) | ReactNode
  sx?: Record<string, React.CSSProperties>
  type?: SensitiveConfigType
}

const DangerZoneBlock: FunctionComponent<DangerZoneBlockProps> = ({ title, component, children, sx, type }) => {
  const { t_i18n } = useFormatter();
  const theme = useTheme<Theme>();

  const {
    isSensitive,
    isAllowed,
  } = useSensitiveModifications(type);

  let currentTitle = title;
  if (isSensitive) {
    currentTitle = (
      <>
        {title}<DangerZoneChip style={{ marginTop: 0, marginLeft: 8 }} />
      </>
    );
  }

  if (component) {
    if (typeof component === 'function') {
      return (
        <>
          <Typography
            variant="h4"
            gutterBottom
            style={{ ...sx?.title, height: '18px' }}
          >
            {currentTitle}
          </Typography>
          {component({
            disabled: isSensitive && !isAllowed,
            style: {
              borderColor: isSensitive ? hexToRGB(theme.palette.dangerZone.main, 0.5) : undefined,
            },
          })}
        </>
      );
    }
    return (
      <>
        <Typography
          variant="h4"
          gutterBottom
          style={{ ...sx?.title, height: '16px' }}
        >
          {currentTitle}
        </Typography>
        {React.cloneElement(component as ReactElement, {
          disabled: isSensitive && !isAllowed,
          style: {
            borderColor: isSensitive ? hexToRGB(theme.palette.dangerZone.main, 0.5) : undefined,
          },
        })}
      </>
    );
  }

  let child;
  if (typeof children === 'function') {
    child = children({ disabled: !isAllowed });
  } else {
    child = React.cloneElement(children as ReactElement, { disabled: !isAllowed, isSensitive });
  }

  if (!isSensitive) {
    return child;
  }

  return (
    <div
      style={{
        border: `1px solid ${hexToRGB(theme.palette.dangerZone.main, 0.5)}`,
        display: 'flex',
        flexDirection: 'column',
        minHeight: theme.spacing(4),
        padding: theme.spacing(1),
        paddingTop: theme.spacing(0.5),
        borderRadius: theme.spacing(0.5),
        ...(sx?.root ?? {}),
      }}
    >
      <Typography
        variant="h4"
        style={{
          color: theme.palette.dangerZone.text?.primary,
          marginTop: theme.spacing(-1.1),
          marginBottom: !title ? theme.spacing(0.5) : 0,
          background: theme.palette.background.default,
          paddingLeft: theme.spacing(1),
          paddingRight: theme.spacing(1),
          fontSize: 10,
          textTransform: 'uppercase',
          fontFamily: '"Geologica", sans-serif',
          fontWeight: 700,
          width: 'fit-content',
          ...(sx?.title ?? {}),
        }}
      >
        {t_i18n('Danger Zone')}{title && (<> - {title}</>)}
      </Typography>
      {child}
    </div>
  );
};

export default DangerZoneBlock;
