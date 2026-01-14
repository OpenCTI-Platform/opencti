import { useTheme } from '@mui/material/styles';
import { Badge, Stack } from '@mui/material';
import Tag from '@common/tag/Tag';
import type { Theme } from './Theme';
import stopEvent from '../utils/domEvent';
import EnrichedTooltip from './EnrichedTooltip';

interface Marking {
  id: string;
  definition?: string | null;
  x_opencti_color?: string | null;
}

interface ItemMarkingsProps {
  markingDefinitions: readonly Marking[];
  limit?: number;
  onClick?: (marking: Marking) => void;
}

interface ChipMarkingProps {
  markingDefinition: Marking;
  onClick?: ItemMarkingsProps['onClick'];
}

const ChipMarking = ({
  markingDefinition,
  onClick,
}: ChipMarkingProps) => {
  const theme = useTheme<Theme>();

  const getColor = () => {
    let color = markingDefinition.x_opencti_color;

    if (color) return color;

    switch (markingDefinition.definition) {
      case 'CD':
      case 'CD-SF':
      case 'DR':
      case 'DR-SF':
      case 'TLP:RED':
      case 'PAP:RED':
        color = theme.palette.severity.critical;
        break;
      case 'TLP:AMBER':
      case 'TLP:AMBER+STRICT':
      case 'PAP:AMBER':
        color = theme.palette.severity.high;
        break;
      case 'NP':
      case 'TLP:GREEN':
      case 'PAP:GREEN':
        color = theme.palette.severity.low;
        break;
      case 'SF':
        color = theme.palette.severity.info;
        break;
      case 'NONE':
        color = undefined;
        break;
      default:
        color = theme.palette.severity.none;
    }

    return color;
  };

  const itemMarkingColor = getColor();
  const hasClickCallback = onClick !== undefined;

  return (
    <Tag
      label={markingDefinition.definition || 'no definition ??'}
      {...itemMarkingColor && { color: itemMarkingColor }}
      {...hasClickCallback && {
        onClick: (e) => {
          stopEvent(e);
          onClick?.(markingDefinition);
        },
      }}
    />
  );
};

const ItemMarkings = ({
  markingDefinitions,
  limit = 0,
  onClick,
}: ItemMarkingsProps) => {
  const markings = markingDefinitions ?? [];

  if (!limit || markings.length <= 1) {
    if (markings.length === 0) {
      return (
        <ChipMarking markingDefinition={{ definition: 'NONE', id: 'NONE' }} />
      );
    }

    return (
      <Stack direction="row" gap={1} flexWrap="wrap">
        {markings.map((markingDefinition) => (
          <ChipMarking
            key={markingDefinition.id}
            markingDefinition={markingDefinition}
            onClick={onClick}
          />
        ))}
      </Stack>
    );
  }

  return (
    <EnrichedTooltip
      placement="bottom"
      title={(
        <Stack direction="row" gap={1} flexWrap="wrap">
          {markings.map((markingDefinition) => (
            <ChipMarking
              key={markingDefinition.id}
              markingDefinition={markingDefinition}
              onClick={onClick}
            />
          ))}
        </Stack>
      )}
    >
      <Stack direction="row" gap={1} flexWrap="wrap">
        {markings.slice(0, limit).map((markingDefinition) => (
          <ChipMarking
            key={markingDefinition.id}
            markingDefinition={markingDefinition}
            onClick={onClick}
          />
        ))}
        <Badge
          variant={markings.length > limit ? 'dot' : 'standard'}
          color="primary"
          sx={{
            '& .MuiBadge-badge': {
              right: 9,
              top: 2,
            },
          }}
        />
      </Stack>
    </EnrichedTooltip>
  );
};

export default ItemMarkings;
