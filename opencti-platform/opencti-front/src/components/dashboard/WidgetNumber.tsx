import { ReactNode } from 'react';
import { useTheme } from '@mui/styles';
import { Box, Stack, Typography } from '@mui/material';
import { Link } from 'react-router';
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
  /**
   * Destination reproducing exactly this number as a filtered list. The
   * component receives a resolved link rather than the drill-down descriptor so
   * it stays presentational, and renders an inert value when it is absent.
   */
  drilldownLink?: string | null;
}

const WidgetNumber = ({
  label,
  value,
  diffLabel,
  diffValue,
  entityType,
  icon,
  action,
  drilldownLink,
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
        {drilldownLink ? (
          <Box
            component={Link}
            to={drilldownLink}
            data-testid={`card-number-${label}`}
            // Without it react-grid-layout turns the click into a widget drag.
            className="noDrag"
            sx={{
              ...valueStyle,
              color: 'inherit',
              textDecoration: 'none',
              '&:hover': { textDecoration: 'underline' },
            }}
          >
            {n(value)}
          </Box>
        ) : (
          <div
            data-testid={`card-number-${label}`}
            style={valueStyle}
          >
            {n(value)}
          </div>
        )}
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
