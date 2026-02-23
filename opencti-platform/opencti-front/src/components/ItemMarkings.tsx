import { useTheme } from '@mui/material/styles';
import { Badge, Stack, Tooltip } from '@mui/material';
import Tag from '@common/tag/Tag';
import type { Theme } from './Theme';
import stopEvent from '../utils/domEvent';
import FieldOrEmpty from './FieldOrEmpty';

interface Marking {
  id: string;
  definition?: string | null;
  x_opencti_color?: string | null;
}

interface ItemMarkingsProps {
  markingDefinitions?: readonly Marking[] | null;
  limit?: number;
  onClick?: (marking: Marking) => void;
}

interface ChipMarkingProps {
  markingDefinition: Marking;
  onClick?: ItemMarkingsProps['onClick'];
  disableTooltip?: boolean;
}

const ChipMarking = ({
  markingDefinition,
  onClick,
  disableTooltip = false,
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
      label={markingDefinition.definition || 'no definition'}
      labelTextTransform="none"
      disableTooltip={disableTooltip}
      {...itemMarkingColor && { color: itemMarkingColor }}
      {...hasClickCallback && {
        onClick: (e) => {
          stopEvent(e);
          onClick?.(markingDefinition);
        },
      }}
      maxWidth={100}
    />
  );
};

const ItemMarkings = ({
  markingDefinitions,
  limit = 0,
  onClick,
}: ItemMarkingsProps) => {
  const theme = useTheme<Theme>();
  const markings = markingDefinitions ?? [];

  if (!limit || markings.length <= 1) {
    return (
      <FieldOrEmpty source={markings}>
        <Stack direction="row" gap={1} flexWrap="wrap">
          {markings.map((markingDefinition) => (
            <ChipMarking
              key={markingDefinition.id}
              markingDefinition={markingDefinition}
              onClick={onClick}
            />
          ))}
        </Stack>
      </FieldOrEmpty>
    );
  }

  const hasOverflow = markings.length > limit;

  // return a multiple marking tags in the tooltip
  return (
    <Tooltip
      title={(
        <Stack
          gap={1}
          direction="row"
          flexWrap="wrap"
          sx={{
            alignItems: 'flex-start',
            p: 1,
          }}
        >
          {
            markings.map((markingDefinition) => (
              <ChipMarking
                key={markingDefinition.id}
                markingDefinition={markingDefinition}
                onClick={onClick}
                disableTooltip
              />
            ))
          }
        </Stack>
      )}
      slotProps={{
        tooltip: {
          sx: {
            backgroundColor: theme.palette.mode === 'light'
              ? theme.palette.common.white
              : theme.palette.common.black,
            maxWidth: 260,
          },
        },
      }}
    >
      <Stack direction="row" gap={1} flexWrap="wrap">
        {markings.slice(0, limit).map((markingDefinition, index) => {
          const isLastVisible = index === limit - 1;
          const showBadge = hasOverflow && isLastVisible;

          return showBadge ? (
            <Badge
              key={markingDefinition.id}
              variant="dot"
              color="primary"
              sx={{
                '& .MuiBadge-badge': {
                  right: 6,
                  top: 2,
                },
              }}
            >
              <ChipMarking
                markingDefinition={markingDefinition}
                onClick={onClick}
                disableTooltip
              />
            </Badge>
          ) : (
            <ChipMarking
              key={markingDefinition.id}
              markingDefinition={markingDefinition}
              onClick={onClick}
              disableTooltip
            />
          );
        })}

      </Stack>
    </Tooltip>
  );
};

export default ItemMarkings;
