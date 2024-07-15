import { styled } from '@mui/styles';
import { FunctionComponent } from 'react';
import type { Theme } from '../../../components/Theme';

interface IconProps {
  icon: React.ElementType,
  color: 'primary'
  | 'secondary'
  | 'error'
  | 'success'
  size: 'small' | 'medium' | 'large'
}
const Icon: FunctionComponent<IconProps> = ({ icon, ...props }) => {
  const Component = icon;
  // eslint-disable-next-line react/react-in-jsx-scope
  return <Component {...props} />;
};

interface FiligranIconProps extends IconProps, Theme {}
const FiligranIcon = styled(Icon)<FiligranIconProps>(({ theme, color, size }) => {
  const sizeMap = {
    small: '1rem',
    medium: '1.25rem',
    large: '1.5rem',
  };
  return {
    color: theme.palette[color].main,
    width: sizeMap[size],
    height: sizeMap[size],
  };
});

export default FiligranIcon;
