import Tag from '@common/tag/Tag';
import { SxProps } from '@mui/material';
import { useFormatter } from './i18n';

interface ItemStatusProps {
  status?: {
    template?: {
      name: string;
      color: string;
    } | null;
  } | null;
  disabled?: boolean;
  onClick?: () => void;
}

const ItemStatus = ({ status, disabled, onClick }: ItemStatusProps) => {
  const { t_i18n } = useFormatter();

  const tagStyle: SxProps = {
    textTransform: 'lowercase',
    '& :first-letter': {
      textTransform: 'uppercase',
    },
  };

  if (status && status.template) {
    return (
      <Tag
        label={status.template.name}
        color={status.template.color}
        sx={tagStyle}
        {...onClick && { onClick: onClick }}
      />
    );
  }

  return (
    <Tag
      label={disabled ? t_i18n('Disabled') : t_i18n('Unknown')}
      sx={tagStyle}
      onClick={onClick}
    />
  );
};

export default ItemStatus;
