import Box from '@mui/material/Box';
// FDS-WORKAROUND #64: the design system ships no skeleton; replace with it once it does.
import Skeleton from '@mui/material/Skeleton';

interface CurationSkeletonProps {
  /** Heights of the blocks, top to bottom, in pixels. */
  blocks?: number[];
}

/** Loading state of the curation surfaces: the shape of the page, never a spinner. */
const CurationSkeleton = ({ blocks = [96, 240, 320] }: CurationSkeletonProps) => (
  <Box sx={{ display: 'flex', flexDirection: 'column', gap: 2 }} aria-hidden data-testid="curation-skeleton">
    {blocks.map((height, index) => <Skeleton key={`${height}-${index}`} variant="rounded" height={height} />)}
  </Box>
);

export default CurationSkeleton;
