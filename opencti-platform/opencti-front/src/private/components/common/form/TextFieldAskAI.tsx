import React, { FunctionComponent, useState } from 'react';
import { AutoAwesomeOutlined } from '@mui/icons-material';
import IconButton from '@mui/material/IconButton';
import EETooltip from '@components/common/entreprise_edition/EETooltip';
import InputAdornment from '@mui/material/InputAdornment';
import MenuItem from '@mui/material/MenuItem';
import Menu from '@mui/material/Menu';
import { v4 as uuid } from 'uuid';
import { graphql, useMutation } from 'react-relay';
import { useFormatter } from '../../../../components/i18n';
import ResponseDialog from '../../../../utils/ai/ResponseDialog';
import useEnterpriseEdition from '../../../../utils/hooks/useEnterpriseEdition';

// region types
interface TextFieldAskAiProps {
  currentValue: string;
  setFieldValue: (value: string) => void;
  format: 'text' | 'html' | 'markdown'
}

const textFieldAskAIFixSpellingMutation = graphql`
  mutation TextFieldAskAIFixSpellingMutation($id: ID!, $content: String!, $format: Format) {
    aiFixSpelling(id: $id, content: $content, format: $format)
  }
`;

const TextFieldAskAI: FunctionComponent<TextFieldAskAiProps> = ({ currentValue, setFieldValue, format = 'text' }) => {
  const { t_i18n } = useFormatter();
  const isEnterpriseEdition = useEnterpriseEdition();
  const [disableResponse, setDisableResponse] = useState(false);
  const [menuOpen, setMenuOpen] = useState<{ open: boolean; anchorEl: HTMLButtonElement | null; }>({ open: false, anchorEl: null });
  const [busId, setBusId] = useState<string | null>(null);
  const [displayAskAI, setDisplayAskAI] = useState(false);
  const handleOpenMenu = (event: React.MouseEvent<HTMLButtonElement, MouseEvent>) => {
    if (isEnterpriseEdition) {
      event.preventDefault();
      setMenuOpen({ open: true, anchorEl: event.currentTarget });
    }
  };
  const handleCloseMenu = () => {
    setMenuOpen({ open: false, anchorEl: null });
  };
  const handleOpenAskAI = () => setDisplayAskAI(true);
  const handleCloseAskAI = () => setDisplayAskAI(false);
  const [commitMutation] = useMutation(textFieldAskAIFixSpellingMutation);
  const handleAskAi = (action: string) => {
    setDisableResponse(true);
    handleCloseMenu();
    const id = uuid();
    setBusId(id);
    handleOpenAskAI();
    switch (action) {
      case 'spelling':
        commitMutation({
          variables: {
            id,
            content: currentValue,
            format,
          },
          onCompleted: () => {
            setDisableResponse(false);
          },
        });
        break;
      default:
        // do nothing
    }
  };
  return (
    <InputAdornment position="end">
      <EETooltip title={t_i18n('Ask AI')}>
        <IconButton
          size="medium"
          color="secondary"
          onClick={handleOpenMenu}
        >
          <AutoAwesomeOutlined fontSize='medium'/>
        </IconButton>
      </EETooltip>
      <Menu
        id="menu-appbar"
        anchorEl={menuOpen.anchorEl}
        open={menuOpen.open}
        onClose={handleCloseMenu}
      >
        <MenuItem onClick={() => handleAskAi('spelling')}>
          {t_i18n('Fix spelling & grammar')}
        </MenuItem>
      </Menu>
      {busId && (
        <ResponseDialog
          id={busId}
          isDisabled={disableResponse}
          isOpen={displayAskAI}
          handleClose={handleCloseAskAI}
          handleAccept={(value) => {
            setFieldValue(value);
            handleCloseAskAI();
          }}
          handleFollowUp={handleCloseAskAI}
          followUpActions={[{ key: 'retry', label: t_i18n('Retry') }]}
          format={format}
        />
      )}
    </InputAdornment>
  );
};

export default TextFieldAskAI;
