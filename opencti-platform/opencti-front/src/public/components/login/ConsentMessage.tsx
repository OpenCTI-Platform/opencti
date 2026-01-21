import Markdown from 'react-markdown';
import { Box, Checkbox } from '@mui/material';
import Card from '../../../components/common/card/Card';
import { ConsentMessageFragment$key } from './__generated__/ConsentMessageFragment.graphql';
import { graphql, useFragment } from 'react-relay';
import { useFormatter } from '../../../components/i18n';

const fragment = graphql`
  fragment ConsentMessageFragment on PublicSettings {
    platform_consent_message
    platform_consent_confirm_text
  }
`;

interface ConsentMessageProps {
  data: ConsentMessageFragment$key;
  onToggle: () => void;
}

const ConsentMessage = ({
  data,
  onToggle,
}: ConsentMessageProps) => {
  const { t_i18n } = useFormatter();
  const {
    platform_consent_message,
    platform_consent_confirm_text,
  } = useFragment(fragment, data);

  if (!platform_consent_message) return null;

  const consentConfirmText = platform_consent_confirm_text
    ? platform_consent_confirm_text
    : t_i18n('I have read and comply with the above statement');

  return (
    <Card variant="outlined">
      <Markdown>{platform_consent_message}</Markdown>
      <Box display="flex" justifyContent="center" alignItems="center">
        <Markdown>{consentConfirmText}</Markdown>
        <Checkbox
          name="consent"
          edge="start"
          onChange={onToggle}
          style={{ margin: 0 }}
        >
        </Checkbox>
      </Box>
    </Card>
  );
};

export default ConsentMessage;
