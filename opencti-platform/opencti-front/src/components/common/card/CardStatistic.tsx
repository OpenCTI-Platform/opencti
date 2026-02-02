import { useTheme } from '@mui/styles';
import { Theme } from '../../Theme';
import Card from './Card';
import { Typography } from '@mui/material';

interface CardStatisticProps {
  label: string;
  value: string;
}

const CardStatistic = ({ label, value }: CardStatisticProps) => {
  const theme = useTheme<Theme>();

  const valueStyle = {
    fontSize: 40,
    lineHeight: 1,
    fontWeight: 600,
  };

  return (
    <Card sx={{ paddingY: 2 }}>
      <Typography
        color={theme.palette.text.light}
        variant="body2"
        gutterBottom
      >
        {label}
      </Typography>

      <div
        data-testid={`card-stat-${label}`}
        style={valueStyle}
      >
        {value}
      </div>
    </Card>
  );
};

export default CardStatistic;
