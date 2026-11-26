import { useTheme } from '@mui/material/styles';
import { Badge, Stack, Tooltip } from '@mui/material';
import Tag from '@common/tag/Tag';
import type { Theme } from './Theme';
import stopEvent from '../utils/domEvent';
import { isWashVisibleOn } from '../utils/Colors';
import { markingTone } from '../utils/severityTone';
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

  // A predefined marking (TLP, PAP, DR/NP/SF/CD) takes the tone every XTM Platform
  // module draws for it, in the single design-system chip style. A custom
  // marking keeps its administrator's colour whenever it can be seen.
  const predefined = markingTone(markingDefinition.definition);
  const stored = markingDefinition.x_opencti_color;
  const itemMarkingColor = predefined === undefined && stored && isWashVisibleOn(stored, theme.palette.background.paper)
    ? stored
    : undefined;
  const itemMarkingTone = predefined ?? (predefined === undefined && !stored ? 'neutral' : undefined);
  const hasClickCallback = onClick !== undefined;

  return (
    <Tag
      label={markingDefinition.definition || 'no definition'}
      labelTextTransform="none"
      disableTooltip={disableTooltip}
      {...itemMarkingColor && { color: itemMarkingColor }}
      {...itemMarkingTone && { severity: itemMarkingTone }}
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
        <Stack
          direction="row"
          sx={{
            gap: 1,
            flexWrap: 'wrap',
          }}
        >
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
          direction="row"
          sx={{
            gap: 1,
            flexWrap: 'wrap',
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
      <Stack
        direction="row"
        sx={{
          gap: 1,
          flexWrap: 'wrap',
        }}
      >
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
