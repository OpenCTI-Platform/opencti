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
    stix: theme.palette.designSystem.tertiary.darkBlue[500] || '#0F2DFF',
    pcre: theme.palette.designSystem.tertiary.darkBlue[300] || '#7587FF',
    sigma: theme.palette.designSystem.tertiary.green[400] || '#41E149',
    snort: theme.palette.designSystem.tertiary.red[200] || '#F8958C',
    suricata: theme.palette.designSystem.tertiary.turquoise[800] || '#005744',
    yara: theme.palette.designSystem.tertiary.red[400] || '#F14337',
    'tanium-signal': theme.palette.designSystem.tertiary.red[500] || '#E51E10',
    spl: theme.palette.designSystem.tertiary.orange[500] || '#E6700F',
    eql: theme.palette.designSystem.tertiary.turquoise[600] || '#00BD94',
    shodan: theme.palette.designSystem.tertiary.red[600] || '#B8180A',
  } as const;
  return (
    <Tag
      label={label}
      color={COLORS[label] ? COLORS[label] : COLORS.stix}
    />
  );
};
export default ItemPatternType;
