import { KeyOutline } from 'mdi-material-ui';
import Button from '../../../components/common/button/Button';
import { APP_BASE_PATH } from '../../../relay/environment';

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

  return (
    <Button
      type="submit"
      variant="secondary"
      component="a"
      startIcon={<KeyOutline fontSize="small" />}
      href={`${APP_BASE_PATH}/auth/${provider}`}
    >
      {name}
    </Button>
  );
};

export default ExternalAuthButton;
