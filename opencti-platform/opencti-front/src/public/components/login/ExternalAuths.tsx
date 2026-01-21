import { graphql } from 'relay-runtime';
import ExternalAuthButton from './ExternalAuthButton';
import { ExternalAuthsFragment$key } from './__generated__/ExternalAuthsFragment.graphql';
import { useFragment } from 'react-relay';
import { isNotEmptyField } from '../../../utils/utils';
import { Stack } from '@mui/material';

const fragment = graphql`
  fragment ExternalAuthsFragment on PublicSettings {
    platform_consent_message
    platform_providers {
      name
      type
      provider
    }
  }
`;

interface ExternalAuthsProps {
  consentValue: boolean;
  data: ExternalAuthsFragment$key;
}

const ExternalAuths = ({
  consentValue,
  data,
}: ExternalAuthsProps) => {
  const {
    platform_providers,
    platform_consent_message,
  } = useFragment(fragment, data);

  const hasConsentMessage = isNotEmptyField(platform_consent_message);
  const authSSOs = platform_providers.filter((p) => p.type === 'SSO');
  const containsSSO = authSSOs.length > 0;

  if (!containsSSO) return null;
  if (hasConsentMessage && !consentValue) return null;

  return (
    <Stack direction="row" gap={1}>
      {authSSOs?.map((value, index) => (
        <ExternalAuthButton
          key={index}
          auth={value}
        />
      ))}
    </Stack>
  );
};

export default ExternalAuths;
