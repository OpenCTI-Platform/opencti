import Tag from '@common/tag/Tag';
import { useTheme } from '@mui/material';
import { FunctionComponent } from 'react';

interface ItemPatternTypeProps {
  label: string;
}

const ItemPatternType: FunctionComponent<ItemPatternTypeProps> = ({
  label,
}) => {
  const theme = useTheme();
  const COLORS: Record<string, string> = {
    stix: 'rgb(32, 58, 246)',
    pcre: 'rgb(92, 123, 245)',
    sigma: theme.palette.success.main,
    snort: 'rgb(231, 133, 109)',
    suricata: theme.palette.success.dark,
    yara: theme.palette.error.main,
    'tanium-signal': theme.palette.error.dark,
    spl: 'rgb(239, 108, 0)',
    eql: 'rgb(32, 201, 151, 0.10)',
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
