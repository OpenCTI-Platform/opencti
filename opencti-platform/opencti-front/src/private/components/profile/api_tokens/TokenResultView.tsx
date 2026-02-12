import Button from '@common/button/Button';
import Alert from '@mui/material/Alert';
import { useTheme } from '@mui/styles';
import { FunctionComponent } from 'react';
import FormButtonContainer from '../../../../components/common/form/FormButtonContainer';
import { useFormatter } from '../../../../components/i18n';
import ItemCopy from '../../../../components/ItemCopy';
import { Theme } from '../../../../components/Theme';
import { Box } from '@mui/material';

interface TokenResultViewProps {
  token: string;
  onClose: () => void;
}

const TokenResultView: FunctionComponent<TokenResultViewProps> = ({
  token,
  onClose,
}) => {
  const { t_i18n } = useFormatter();
  const theme = useTheme<Theme>();
  // No explicit focus on Close button anymore, handled by ItemCopy focusOnMount
  // useEffect(() => { ... }, []);

  return (
    <div>
      <Alert severity="success" variant="outlined" sx={{ mb: 2 }}>
        <strong>{t_i18n('Token generated successfully')}</strong>
        <br />
        {t_i18n('Make sure to copy your new personal access token now. You won\'t be able to see it again!')}
      </Alert>

      <Box
        sx={{
          padding: 2,
          backgroundColor: theme.palette.designSystem.background.main,
          borderRadius: 2,
        }}
      >
        <ItemCopy content={token} focusOnMount={true} />
      </Box>

      <FormButtonContainer>
        <Button onClick={onClose}>
          {t_i18n('Close')}
        </Button>
      </FormButtonContainer>
    </div>
  );
};

export default TokenResultView;
