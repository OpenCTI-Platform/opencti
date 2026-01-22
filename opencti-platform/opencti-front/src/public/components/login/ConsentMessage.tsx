import { Box, Checkbox } from '@mui/material';
import Card from '../../../components/common/card/Card';
import { ConsentMessageFragment$key } from './__generated__/ConsentMessageFragment.graphql';
import { graphql, useFragment } from 'react-relay';
import { useFormatter } from '../../../components/i18n';
import LoginMarkdown from './LoginMarkdown';

const fragment = graphql`
  fragment ConsentMessageFragment on PublicSettings {
    platform_consent_message
    platform_consent_confirm_text
  }
`;

interface ConsentMessageProps {
  data: ConsentMessageFragment$key;
  value: boolean;
  onToggle: () => void;
}

const ConsentMessage = ({
  data,
  value,
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
    <Card variant="outlined" padding="horizontal">
      <LoginMarkdown>
        {platform_consent_message}
      </LoginMarkdown>
      <Box
        mt={1}
        gap={0.5}
        display="flex"
        alignItems="start"
        sx={{ cursor: 'pointer' }}
        onClick={onToggle}
      >
        <Checkbox
          name="consent"
          edge="start"
          size="small"
          checked={value}
          onChange={onToggle}
          style={{ margin: 0, padding: 0 }}
        >
        </Checkbox>
        <LoginMarkdown>
          {consentConfirmText}
        </LoginMarkdown>
      </Box>
    </Card>
  );
};

export default ConsentMessage;
