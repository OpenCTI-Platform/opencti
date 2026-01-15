import Tag from '@common/tag/Tag';
import { useTheme } from '@mui/styles';
import { FunctionComponent } from 'react';
import { Theme } from '../components/Theme';

interface ItemPatternTypeProps {
  label: string;
}

const ItemPatternType: FunctionComponent<ItemPatternTypeProps> = ({
  label,
}) => {
  const theme = useTheme<Theme>();
  const COLORS: Record<string, string> = {
    stix: theme.palette.tertiary.darkBlue[500] || '#0F2DFF',
    pcre: theme.palette.tertiary.darkBlue[300] || '#7587FF',
    sigma: theme.palette.tertiary.green[400] || '#41E149',
    snort: theme.palette.tertiary.red[200] || '#F8958C',
    suricata: theme.palette.tertiary.turquoise[800] || '#005744',
    yara: theme.palette.tertiary.red[400] || '#F14337',
    'tanium-signal': theme.palette.tertiary.red[500] || '#E51E10',
    spl: theme.palette.tertiary.orange[500] || '#E6700F',
    eql: theme.palette.tertiary.turquoise[600] || '#00BD94',
    shodan: theme.palette.tertiary.red[600] || '#B8180A',
  } as const;
  return (
    <Tag
      label={label}
      color={COLORS[label] ? COLORS[label] : COLORS.stix}
    />
  );
};
export default ItemPatternType;
