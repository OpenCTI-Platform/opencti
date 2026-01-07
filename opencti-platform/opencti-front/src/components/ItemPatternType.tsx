import Tag from '@common/tag/Tag';
import { FunctionComponent } from 'react';

const COLORS: Record<string, string> = {
  stix: 'rgb(32, 58, 246)',
  pcre: 'rgb(92, 123, 245)',
  sigma: 'rgb(76, 175, 80)',
  snort: 'rgb(231, 133, 109)',
  suricata: 'rgb(0, 105, 92)',
  yara: 'rgb(244, 67, 54)',
  'tanium-signal': 'rgb(243, 25, 25)',
  spl: 'rgb(239, 108, 0)',
  eql: 'rgb(32, 201, 151, 0.10)',
  shodan: 'rgb(185, 52, 37)',
} as const;

interface ItemPatternTypeProps {
  label: string;
}

const ItemPatternType: FunctionComponent<ItemPatternTypeProps> = ({
  label,
}) => {
  return (
    <Tag
      label={label}
      color={COLORS[label] ? COLORS[label] : COLORS.stix}
    />
  );
};
export default ItemPatternType;
