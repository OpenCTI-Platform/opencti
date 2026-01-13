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
    stix: theme.palette.primary.main || '#0fbcff',
    pcre: theme.palette.primary.light || '#B2ECFF',
    sigma: theme.palette.success.main || '#17AB1F',
    snort: 'rgb(231, 133, 109)',
    suricata: theme.palette.success.dark || '#094E0B',
    yara: theme.palette.error.main || '#F14337',
    'tanium-signal': theme.palette.error.dark || '#881106',
    spl: 'rgb(239, 108, 0)',
    eql: 'rgba(32, 201, 151, 0.10)',
    shodan: 'rgb(185, 52, 37)',
  } as const;
  return (
    <Tag
      label={label}
      color={COLORS[label] ? COLORS[label] : COLORS.stix}
    />
  );
};
export default ItemPatternType;
