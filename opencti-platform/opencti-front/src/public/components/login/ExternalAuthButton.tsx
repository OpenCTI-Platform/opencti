import { Facebook, Github, Google, KeyOutline } from 'mdi-material-ui';
import { useTheme } from '@mui/styles';
import { SxProps } from '@mui/material';
import Button from '../../../components/common/button/Button';
import { APP_BASE_PATH } from '../../../relay/environment';
import type { Theme } from '../../../components/Theme';

interface ExternalAuthButtonProps {
  auth: {
    provider?: string | null;
    name: string;
  };
}

const ExternalAuthButton = ({
  auth,
}: ExternalAuthButtonProps) => {
  const { provider, name } = auth;
  const theme = useTheme<Theme>();

  let style: SxProps = {
    color: theme.palette.ee.main,
    borderColor: theme.palette.ee.main,
    '&:hover': {
      backgroundColor: 'rgba(0, 121, 107, .1)',
      borderColor: theme.palette.ee.main,
      color: theme.palette.ee.main,
    },
  };
  switch (provider) {
    case 'facebook':
      style = {
        color: '#4267b2',
        borderColor: '#4267b2',
        '&:hover': {
          backgroundColor: 'rgba(55, 74, 136, .1)',
          borderColor: '#374a88',
          color: '#374a88',
        },
      };
      break;
    case 'google':
      style = {
        color: theme.palette.error.main,
        borderColor: theme.palette.error.main,
        '&:hover': {
          backgroundColor: 'rgba(189, 51, 46, .1)',
          borderColor: theme.palette.error.main,
          color: theme.palette.error.main,
        },
      };
      break;
    case 'github':
      style = {
        color: '#5b5b5b',
        borderColor: '#5b5b5b',
        '&:hover': {
          backgroundColor: 'rgba(54, 54, 54, .1)',
          borderColor: '#363636',
          color: '#363636',
        },
      };
      break;
  }

  let icon = <KeyOutline fontSize="small" />;
  switch (provider) {
    case 'facebook':
      icon = <Facebook fontSize="small" />;
      break;
    case 'google':
      icon = <Google fontSize="small" />;
      break;
    case 'github':
      icon = <Github fontSize="small" />;
      break;
  }

  return (
    <Button
      type="submit"
      variant="secondary"
      component="a"
      href={`${APP_BASE_PATH}/auth/${provider}`}
      sx={style}
    >
      {icon}
      {name}
    </Button>
  );
};

export default ExternalAuthButton;
