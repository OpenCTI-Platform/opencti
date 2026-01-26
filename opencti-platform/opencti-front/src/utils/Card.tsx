import { DraftChip } from '@components/common/draft/DraftChip';
import { DraftVersion } from '@components/common/cards/GenericAttackCard';
import { Stack, Tooltip, Typography } from '@mui/material';
import { APP_BASE_PATH } from '../relay/environment';

export interface toEdgesLocated {
  edges: ReadonlyArray<{ node: { to: { x_opencti_aliases?: ReadonlyArray<string | null> | null; name?: string } | null } }>;
}

interface EntityCard {
  name: string;
  draftVersion?: DraftVersion | null;
  countryFlag?: toEdgesLocated | null | undefined;
}

export const renderCardTitle = (entity: EntityCard) => {
  const country = entity.countryFlag?.edges[0]?.node?.to;
  const flag = country?.x_opencti_aliases
    ? country.x_opencti_aliases.find((a) => a?.length === 2) : null;

  return (
    <Stack direction="row">
      <Typography
        variant="h3"
        sx={{
          fontSize: 16,
          fontWeight: 700,
          mb: 0,
          whiteSpace: 'nowrap',
          overflow: 'hidden',
          textOverflow: 'ellipsis',
        }}
      >
        {entity.name}
      </Typography>
      {country && flag && (
        <Tooltip title={country.name}>
          <img
            style={{ width: 20 }}
            src={`${APP_BASE_PATH}/static/flags/4x3/${flag.toLowerCase()}.svg`}
            alt={country.name}
          />
        </Tooltip>
      )}
      {entity.draftVersion && (
        <DraftChip style={{ marginLeft: 10 }} />
      )}
    </Stack>
  );
};
