import React, { CSSProperties } from 'react';
import { ArrowDropDownOutlined, ArrowDropUpOutlined } from '@mui/icons-material';
import { Box } from '@components';
import { useFormatter } from '../../../../components/i18n';

const sortHeaderStyle: Record<string, CSSProperties> = {
  iconSort: {
    position: 'absolute',
    margin: '0 0 0 5px',
    padding: 0,
    top: '0px',
  },
  name: {
    float: 'left',
    width: '25%',
    fontSize: 12,
    fontWeight: '700',
  },
  connector_type: {
    float: 'left',
    fontSize: 12,
    fontWeight: '700',
  },
  auto: {
    float: 'left',
    fontSize: 12,
    fontWeight: '700',
  },
  messages: {
    float: 'left',
    fontSize: 12,
    fontWeight: '700',
  },
  active: {
    float: 'left',
    fontSize: 12,
    fontWeight: '700',
  },
  updated_at: {
    float: 'left',
    width: '15%',
    fontSize: 12,
    fontWeight: '700',
  },
  is_managed: {
    float: 'left',
    fontSize: 12,
    fontWeight: '700',
  },
};

interface SortConnectorsHeaderProps {
  field: string
  label: string
  isSortable: boolean
  orderAsc: boolean
  sortBy: string
  reverseBy: (field: string) => void
}

const SortConnectorsHeader: React.FC<SortConnectorsHeaderProps> = ({ field, label, isSortable, orderAsc, sortBy, reverseBy }) => {
  const { t_i18n } = useFormatter();

  const sortComponent = orderAsc ? (
    <ArrowDropDownOutlined sx={sortHeaderStyle.iconSort} />
  ) : (
    <ArrowDropUpOutlined sx={sortHeaderStyle.iconSort} />
  );

  if (isSortable) {
    return (
      <Box
        sx={sortHeaderStyle[field]}
        onClick={() => reverseBy(field)}
      >
        <span>{t_i18n(label)}</span>
        {sortBy === field ? sortComponent : ''}
      </Box>
    );
  }

  return (
    <div style={sortHeaderStyle[field]}>
      <span>{t_i18n(label)}</span>
    </div>
  );
};

export default SortConnectorsHeader;
