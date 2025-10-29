import React from 'react';
import { useTheme } from '@mui/material/styles';
import { Tooltip, Chip, Grid, Badge } from '@mui/material';
import type { Theme } from './Theme';
import stopEvent from '../utils/domEvent';
import EnrichedTooltip from './EnrichedTooltip';

interface Marking {
  id: string
  definition?: string | null
  x_opencti_color?: string | null
}

interface ItemMarkingsProps {
  markingDefinitions: readonly Marking[]
  variant?: string
  limit?: number
  onClick?: (marking: Marking) => void
}

interface ChipMarkingProps {
  markingDefinition: Marking
  isInTooltip?: boolean
  withTooltip?: boolean
  variant?: ItemMarkingsProps['variant']
  onClick?: ItemMarkingsProps['onClick']
}

const ChipMarking = ({
  markingDefinition,
  isInTooltip = false,
  withTooltip = false,
  variant,
  onClick,
}: ChipMarkingProps) => {
  const theme = useTheme<Theme>();

  const monochromeStyle = (color: string) => {
    if (color === 'transparent') {
      const transparentColor = theme.palette.mode === 'light' ? '#2b2b2b' : '#ffffff';
      return {
        backgroundColor: 'transparent',
        color: transparentColor,
        border: `2px solid ${transparentColor}`,
      };
    }
    if (theme.palette.mode === 'light' && color === '#ffffff') {
      // White alternative for light mode.
      return {
        backgroundColor: '#ffffff',
        color: '#2b2b2b',
        border: '2px solid #2b2b2b',
      };
    }
    return {
      backgroundColor: `${color}33`, // 20% opacity
      color: theme.palette.text?.primary,
      border: `2px solid ${color}`,
    };
  };

  const getStyle = () => {
    let color = markingDefinition.x_opencti_color;
    if (!color) {
      switch (markingDefinition.definition) {
        case 'CD':
        case 'CD-SF':
        case 'DR':
        case 'DR-SF':
        case 'TLP:RED':
        case 'PAP:RED':
          color = '#c62828';
          break;
        case 'TLP:AMBER':
        case 'TLP:AMBER+STRICT':
        case 'PAP:AMBER':
          color = '#d84315';
          break;
        case 'NP':
        case 'TLP:GREEN':
        case 'PAP:GREEN':
          color = '#2e7d32';
          break;
        case 'SF':
          color = '#283593';
          break;
        case 'NONE':
          color = 'transparent';
          break;
        default:
          color = '#ffffff';
      }
    }
    return monochromeStyle(color);
  };

  let width: number | string = variant === 'inList' ? 90 : 120;
  if (isInTooltip) width = '100%';

  return (
    <Tooltip title={withTooltip ? markingDefinition.definition : undefined}>
      <Chip
        label={markingDefinition.definition}
        style={{
          fontSize: 12,
          lineHeight: '12px',
          borderRadius: 4,
          marginRight: 7,
          marginBottom: variant === 'inList' ? 0 : 7,
          height: variant === 'inList' ? 20 : 25,
          cursor: onClick ? 'pointer' : 'default',
          width,
          ...getStyle(),
        }}
        onClick={(e) => {
          stopEvent(e);
          onClick?.(markingDefinition);
        }}
      />
    </Tooltip>
  );
};

const ItemMarkings = ({
  variant = '',
  markingDefinitions,
  limit = 0,
  onClick,
}: ItemMarkingsProps) => {
  const markings = markingDefinitions ?? [];

  if (!limit || markings.length <= 1) {
    return (
      <span>
        {markings.length === 0
          ? <ChipMarking
              markingDefinition={{ definition: 'NONE', id: 'NONE' }}
              withTooltip
              variant={variant}
            />
          : markings.map((markingDefinition) => (
            <ChipMarking
              key={markingDefinition.id}
              markingDefinition={markingDefinition}
              withTooltip
              variant={variant}
              onClick={onClick}
            />
          ))}
      </span>
    );
  }
  return (
    <EnrichedTooltip
      placement="bottom"
      title={(
        <Grid container={true} spacing={3}>
          {markings.map((markingDefinition) => (
            <Grid key={markingDefinition.id} item xs={6}>
              <ChipMarking
                markingDefinition={markingDefinition}
                withTooltip
                isInTooltip
                variant={variant}
                onClick={onClick}
              />
            </Grid>
          ))}
        </Grid>
      )}
    >
      <div style={{ display: 'flex', alignItems: 'center' }}>
        <Badge
          variant={markings.length > limit ? 'dot' : 'standard'}
          color="primary"
          sx={{
            '& .MuiBadge-badge': {
              right: 8,
              top: 4,
            },
          }}
        >
          {markings.slice(0, limit).map((markingDefinition) => (
            <ChipMarking
              key={markingDefinition.id}
              markingDefinition={markingDefinition}
              variant={variant}
              onClick={onClick}
            />
          ))}
        </Badge>
      </div>
    </EnrichedTooltip>
  );
};

export default ItemMarkings;
