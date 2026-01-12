import { DraftChip } from '@components/common/draft/DraftChip';
import { DraftVersion } from '@components/common/cards/GenericAttackCard';
import { Typography } from '@mui/material';

export interface toEdgesLocated {
  edges: ReadonlyArray<{ node: { to: { x_opencti_aliases?: ReadonlyArray<string | null> | null; name?: string } | null } }>;
}

export const renderCardTitle = (entity: { name: string; draftVersion?: DraftVersion | null }) => {
  return (
    <div>
      <Typography
        variant="h3"
        sx={{
          fontSize: 16,
          fontWeight: 700,
          mb: 0,
          whiteSpace: 'nowrap',
          overflow: 'hidden',
          textOverflow: 'ellipsis',
          minWidth: 0,
        }}
      >
        {entity.name}
      </Typography>
      {entity.draftVersion && (
        <DraftChip style={{ marginLeft: 10 }} />
      )}
    </div>
  );
};
