import { ReactNode } from 'react';
import { useTheme } from '@mui/styles';
import { Stack, Typography } from '@mui/material';
import { Theme } from '../../Theme';
import { useFormatter } from '../../i18n';
import NumberDifference from '../../NumberDifference';
import ItemIcon from '../../ItemIcon';
import Card from './Card';

interface CardNumberProps {
  label: string;
  value: number;
  diffLabel?: string;
  diffValue?: number;
  entityType?: string;
  icon?: ReactNode;
}

const CardNumber = ({
  label,
  value,
  diffLabel,
  diffValue,
  entityType,
  icon,
}: CardNumberProps) => {
  const { n } = useFormatter();
  const theme = useTheme<Theme>();

  const valueStyle = {
    fontSize: 42,
    lineHeight: 1,
    fontWeight: 600,
  };

  return (
    <Card sx={{ paddingY: 2 }}>
      <Stack direction="row" alignItems="start" gap={1}>
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
    </Card>
  );
};

export default CardNumber;
