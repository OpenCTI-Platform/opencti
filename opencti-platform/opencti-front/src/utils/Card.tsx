import { DraftChip } from '@components/common/draft/DraftChip';
import { DraftVersion } from '@components/common/cards/GenericAttackCard';
import { Stack, Tooltip, Typography } from '@mui/material';
import { findFlagUrl } from '../utils/flags';

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
  const flagUrl = findFlagUrl(country?.x_opencti_aliases);

  return (
    <Stack direction="row" gap={1}>
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
      {country && flagUrl && (
        <Tooltip title={country.name}>
          <img
            style={{ width: 20 }}
            src={flagUrl}
            alt={country.name}
          />
        </Tooltip>
      )}
      {entity.draftVersion && (
        <DraftChip />
      )}
    </Stack>
  );
};
