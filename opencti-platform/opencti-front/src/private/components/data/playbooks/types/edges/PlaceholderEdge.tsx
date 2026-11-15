import { EdgeProps, getStraightPath } from 'reactflow';
import { useTheme } from '@mui/material/styles';
import type { Theme } from '../../../../../../components/Theme';

// The short dashed stub from a free out port to its add button.
export default function PlaceholderEdge({
  id,
  sourceX,
  sourceY,
  targetX,
  targetY,
}: EdgeProps) {
  const theme = useTheme<Theme>();
  const [edgePath] = getStraightPath({ sourceX, sourceY, targetX, targetY });
  return (
    <path
      id={id}
      style={{
        strokeWidth: 1,
        strokeDasharray: '3 3',
        stroke: theme.palette.text?.secondary,
        fill: 'none',
      }}
      d={edgePath}
    />
  );
}
