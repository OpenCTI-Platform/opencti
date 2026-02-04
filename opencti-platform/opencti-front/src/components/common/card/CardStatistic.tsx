import { ReactNode } from 'react';
import { useTheme } from '@mui/styles';
import { Theme } from '../../Theme';
import Card from './Card';
import { Stack, Typography } from '@mui/material';

interface CardStatisticProps {
  label: string;
  value: string | ReactNode;
  icon?: ReactNode;
}

const CardStatistic = ({
  label,
  value,
  icon,
}: CardStatisticProps) => {
  const theme = useTheme<Theme>();

  const valueStyle = {
    fontSize: 32,
    lineHeight: 1,
    fontWeight: 600,
  };

  return (
    <Card sx={{ paddingY: 2 }}>
      <Stack height="100%" justifyContent="space-between">
        <Typography
          color={theme.palette.text.light}
          variant="body2"
          gutterBottom
        >
          {label}
        </Typography>

        <Stack
          direction="row"
          justifyContent="space-between"
          alignItems="center"
        >
          <div
            data-testid={`card-stat-${label}`}
            style={valueStyle}
          >
            {value}
          </div>
          {icon}
        </Stack>
      </Stack>
    </Card>
  );
};

export default CardStatistic;
