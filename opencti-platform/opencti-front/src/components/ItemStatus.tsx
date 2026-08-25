import Tag from '@common/tag/Tag';
import Box from '@mui/material/Box';
import { SxProps } from '@mui/material';
import { alpha } from '@mui/material/styles';
import { useFormatter } from './i18n';

interface ItemStatusProps {
  status?: {
    order?: number | null;
    template?: {
      name: string;
      color: string;
    } | null;
  } | null;
  disabled?: boolean;
  onClick?: () => void;
  // 'chip' (default) keeps the pill/Chip look used in tables and lists; 'plain' renders the status
  // as unadorned text at the same font size as neighboring action buttons (14px).
  variant?: 'chip' | 'plain';
}

const ItemStatus = ({ status, disabled, onClick, variant = 'chip' }: ItemStatusProps) => {
  const { t_i18n } = useFormatter();

  const tagStyle: SxProps = {
    textTransform: 'lowercase',
    '& :first-letter': {
      textTransform: 'uppercase',
    },
  };

  // Position of this status within its workflow (e.g. NEW=1) — omitted when the caller's query
  // didn't select `order`, or the underlying Status has none.
  const hasOrder = typeof status?.order === 'number';
  const chipOrderBadge = hasOrder ? (
    <Box
      component="span"
      sx={{
        fontSize: 11,
        fontWeight: 700,
        lineHeight: '16px',
        borderRadius: '4px',
        px: '4px',
        bgcolor: 'background.default',
      }}
    >
      {status?.order}
    </Box>
  ) : undefined;
  // In the plain variant only the number carries the status color; the label stays white.
  const plainOrderBadge = hasOrder ? (
    <Box
      component="span"
      sx={{
        fontSize: 11,
        fontWeight: 700,
        lineHeight: '16px',
        borderRadius: '4px',
        px: '4px',
        color: status?.template?.color,
        bgcolor: status?.template?.color ? alpha(status.template.color, 0.15) : undefined,
      }}
    >
      {status?.order}
    </Box>
  ) : undefined;

  if (status && status.template) {
    if (variant === 'plain') {
      return (
        <Box
          component="span"
          onClick={onClick}
          sx={{
            display: 'inline-flex',
            alignItems: 'center',
            gap: '4px',
            fontSize: '14px',
            color: 'common.white',
            cursor: onClick ? 'pointer' : 'inherit',
          }}
        >
          {plainOrderBadge}
          {status.template.name}
        </Box>
      );
    }
    return (
      <Tag
        label={status.template.name}
        color={status.template.color}
        icon={chipOrderBadge}
        sx={tagStyle}
        {...onClick && { onClick: onClick }}
      />
    );
  }

  if (variant === 'plain') {
    return (
      <Box
        component="span"
        onClick={onClick}
        sx={{ fontSize: '14px', color: 'common.white', cursor: onClick ? 'pointer' : 'inherit' }}
      >
        {disabled ? t_i18n('Disabled') : t_i18n('Unknown')}
      </Box>
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
