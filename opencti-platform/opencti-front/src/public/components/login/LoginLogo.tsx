import { graphql } from 'relay-runtime';
import { useFragment } from 'react-relay';
import { LoginLogoFragment$key } from './__generated__/LoginLogoFragment.graphql';
import { isEmptyField } from '../../../utils/utils';
import { fileUri } from '../../../relay/environment';
import ResaaCtipLogo from '../../../static/images/logo_resaactip';

const fragment = graphql`
  fragment LoginLogoFragment on PublicSettings {
    platform_theme {
      theme_logo_login
    }
  }
`;

interface LoginLogoProps {
  data: LoginLogoFragment$key;
}

const LoginLogo = ({ data }: LoginLogoProps) => {
  const { platform_theme } = useFragment(fragment, data);
  const customLogo = platform_theme?.theme_logo_login;

  if (!isEmptyField(customLogo)) {
    return (
      <img
        src={customLogo}
        alt="ResaaCTIP Logo"
        height={40}
      />
    );
  }

  return <ResaaCtipLogo />;
};

export default LoginLogo;
