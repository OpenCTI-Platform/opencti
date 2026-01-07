import Tag from '@common/tag/Tag';
import { SxProps } from '@mui/material';
import { useFormatter } from './i18n';

// const styles = () => ({
//   chip: {
//     fontSize: 12,
//     lineHeight: '12px',
//     height: 25,
//     marginRight: 7,
//     borderRadius: 4,
//     width: 100,
//   },
//   chipInList: {
//     ...chipInListBasicStyle,
//     lineHeight: '12px',
//     width: 80,
//   },
//   chipInline: {
//     fontSize: 12,
//     lineHeight: '10px',
//     height: 20,
//     float: 'left',
//     borderRadius: 4,
//   },
// });

interface ItemStatusProps {
  status?: {
    template: {
      name: string;
      color: string;
    };
  };
  disabled?: boolean;
}

const ItemStatus = ({ status, disabled }: ItemStatusProps) => {
  // const { classes, t, status, variant, disabled, onClick } = props;
  // let style = classes.chip;
  // if (variant === 'inList') {
  //   style = classes.chipInList;
  // } else if (variant === 'inLine') {
  //   style = classes.chipInline;
  // }

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
      />
    );
  }

  return (
    <Tag
      label={disabled ? t_i18n('Disabled') : t_i18n('Unknown')}
      sx={tagStyle}
    />
  );
};

export default ItemStatus;

// ItemStatus.propTypes = {
//   classes: PropTypes.object.isRequired,
//   onClick: PropTypes.func,
//   status: PropTypes.object,
//   variant: PropTypes.string,
//   t: PropTypes.func,
//   disabled: PropTypes.bool,
// };

// export default compose(inject18n, withStyles(styles))(ItemStatus);
