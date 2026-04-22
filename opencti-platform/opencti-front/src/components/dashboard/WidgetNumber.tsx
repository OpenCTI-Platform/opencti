import { ReactNode } from 'react';
import { useTheme } from '@mui/styles';
import { Stack, Typography } from '@mui/material';
import { useFormatter } from '../i18n';
import { Theme } from '../Theme';
import NumberDifference from '../NumberDifference';
import ItemIcon from '../ItemIcon';

export interface WidgetNumberProps {
  label: string;
  value: number;
  diffLabel?: string;
  diffValue?: number;
  entityType?: string;
  icon?: ReactNode;
  action?: ReactNode;
}

const WidgetNumber = ({
  label,
  value,
  diffLabel,
  diffValue,
  entityType,
  icon,
  action,
}: WidgetNumberProps) => {
  const { n } = useFormatter();
  const theme = useTheme<Theme>();

  const valueStyle = {
    fontSize: 32,
    lineHeight: 1,
    fontWeight: 600,
  };

  return (
    <Stack height="100%" justifyContent="space-between">
      <Stack direction="row" alignItems="start">
        <Stack direction="row" alignItems="start" gap={1} flex={1}>
          <Typography
            color={theme.palette.text.light}
            variant="body2"
            gutterBottom
          >
            {label}
          </Typography>
          {diffValue !== undefined && diffLabel && (
            <NumberDifference
              value={diffValue}
              description={diffLabel}
            />
          )}
        </Stack>
        {action}
      </Stack>

      <Stack
        direction="row"
        justifyContent="space-between"
        alignItems="center"
      >
        <div
          data-testid={`card-number-${label}`}
          style={valueStyle}
        >
          {n(value)}
        </div>
        {entityType && (
          <ItemIcon
            type={entityType}
            size="large"
            color={theme.palette.text.secondary}
            style={{ opacity: 0.35 }}
          />
        )}
        {icon}
      </Stack>
    </Stack>
  );
};

export default WidgetNumber;
