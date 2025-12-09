import { CSSProperties, PropsWithChildren, ReactNode } from 'react';
import CardTitle from './CardTitle';
import { Theme } from '../../Theme';
import { useTheme } from '@mui/styles';

interface CardProps extends PropsWithChildren {
  title: string
  action?: ReactNode
}

const Card = ({
  title,
  children,
  action
}: CardProps) => {
  const theme = useTheme<Theme>();
  
  const containerStyle: CSSProperties = {
    padding: theme.spacing(3),
    borderRadius: theme.spacing(.5),
    background: theme.palette.background.secondary
  };

  return (
    <div>
      <CardTitle action={action}>
        {title}
      </CardTitle>
      <div style={containerStyle}>
        {children}
      </div>
    </div>
  );
};

export default Card;