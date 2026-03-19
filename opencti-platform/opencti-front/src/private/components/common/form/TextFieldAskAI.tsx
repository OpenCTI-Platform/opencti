import IconButton from '@common/button/IconButton';
import FiligranIcon from '@components/common/FiligranIcon';
import InputAdornment from '@mui/material/InputAdornment';
import Menu from '@mui/material/Menu';
import MenuItem from '@mui/material/MenuItem';
import { useTheme } from '@mui/styles';
import { LogoXtmOneIcon } from 'filigran-icon';
import React, { FunctionComponent, useRef, useState } from 'react';
import { v4 as uuid } from 'uuid';
import { useFormatter } from '../../../../components/i18n';
import EETooltip from '../entreprise_edition/EETooltip';

import type { Theme } from '../../../../components/Theme';
import ResponseDialog from '../../../../utils/ai/ResponseDialog';
import useAI from '../../../../utils/hooks/useAI';
import useEnterpriseEdition from '../../../../utils/hooks/useEnterpriseEdition';

// region types
export type AgentAction = 'spelling' | 'shorter' | 'longer' | 'tone' | 'summarize' | 'explain';

export interface AgentMode {
  intent: string;
  action: AgentAction;
  inputContent: string;
  format: string;
}

interface TextFieldAskAiProps {
  currentValue: string;
  setFieldValue: (value: string) => void;
  format: 'text' | 'html' | 'markdown';
  variant?: 'markdown' | 'html' | 'text' | null;
  disabled?: boolean;
  style?: object;
}

const TextFieldAskAI: FunctionComponent<TextFieldAskAiProps> = ({
  currentValue,
  setFieldValue,
  variant,
  format = 'text',
  disabled,
  style,
}) => {
  const theme = useTheme<Theme>();
  const { t_i18n } = useFormatter();
  const isEnterpriseEdition = useEnterpriseEdition();
  const { fullyActive } = useAI();
  const [content, setContent] = useState('');
  const menuId = useRef(`ask-ai-menu-${uuid()}`).current;
  const [menuOpen, setMenuOpen] = useState<{ open: boolean; anchorEl: HTMLButtonElement | null }>({ open: false, anchorEl: null });
  const [busId, setBusId] = useState<string | null>(null);
  const [displayAskAI, setDisplayAskAI] = useState(false);
  const [agentMode, setAgentMode] = useState<AgentMode | null>(null);

  const handleOpenMenu = (event: React.MouseEvent<HTMLButtonElement, MouseEvent>) => {
    if (isEnterpriseEdition) {
      event.preventDefault();
      setMenuOpen({ open: true, anchorEl: event.currentTarget });
    }
  };
  const handleCloseMenu = () => {
    setMenuOpen({ open: false, anchorEl: null });
  };
  const handleCloseAskAI = () => {
    setContent('');
    setDisplayAskAI(false);
    setAgentMode(null);
    setBusId(null);
  };

  const intentForAction: Record<AgentAction, string> = {
    spelling: 'fix.spelling',
    shorter: 'make.it.shorter',
    longer: 'make.it.longer',
    tone: 'change.tone',
    summarize: 'summarize',
    explain: 'explain',
  };

  const handleAgentAction = (action: AgentAction) => {
    handleCloseMenu();
    const id = uuid();
    setBusId(id);
    setContent('');
    setAgentMode({
      intent: intentForAction[action],
      action,
      inputContent: currentValue,
      format,
    });
    setDisplayAskAI(true);
  };

  const renderButton = () => {
    const isContentTooShort = currentValue.length < 2;
    const isButtonDisabled = disabled || isContentTooShort;
    const tooltipTitle = isContentTooShort
      ? t_i18n('Add more content before using AI')
      : t_i18n('Ask AI');
    return (
      <>
        <EETooltip forAi={true} title={tooltipTitle}>
          <span style={{ display: 'inline-flex' }}>
            <IconButton
              size="small"
              onClick={(event) => ((isEnterpriseEdition && fullyActive) ? handleOpenMenu(event) : null)}
              disabled={isButtonDisabled}
              style={{ color: isButtonDisabled ? (theme.palette.action?.disabled ?? 'rgba(255,255,255,0.3)') : theme.palette.ai.main }}
            >
              <FiligranIcon icon={LogoXtmOneIcon} size="small" />
            </IconButton>
          </span>
        </EETooltip>
        <Menu
          id={menuId}
          anchorEl={menuOpen.anchorEl}
          open={menuOpen.open}
          onClose={handleCloseMenu}
        >
          <MenuItem onClick={() => handleAgentAction('spelling')}>
            {t_i18n('Fix spelling & grammar')}
          </MenuItem>
          <MenuItem onClick={() => handleAgentAction('shorter')}>
            {t_i18n('Make it shorter')}
          </MenuItem>
          <MenuItem onClick={() => handleAgentAction('longer')}>
            {t_i18n('Make it longer')}
          </MenuItem>
          <MenuItem onClick={() => handleAgentAction('tone')}>
            {t_i18n('Change tone')}
          </MenuItem>
          <MenuItem onClick={() => handleAgentAction('summarize')}>
            {t_i18n('Summarize')}
          </MenuItem>
          <MenuItem onClick={() => handleAgentAction('explain')}>
            {t_i18n('Explain')}
          </MenuItem>
        </Menu>
        {busId && (
          <ResponseDialog
            id={busId}
            isDisabled={false}
            isOpen={displayAskAI}
            handleClose={handleCloseAskAI}
            content={content}
            setContent={setContent}
            handleAccept={(value) => {
              setFieldValue(value);
              handleCloseAskAI();
            }}
            handleFollowUp={handleCloseAskAI}
            followUpActions={[]}
            format={format}
            isAcceptable={true}
            agentMode={agentMode}
          />
        )}
      </>
    );
  };
  if (variant === 'markdown') {
    return (
      <div style={style || { position: 'absolute', top: 17, right: 0, paddingTop: 4 }}>
        {fullyActive && renderButton()}
      </div>
    );
  }
  if (variant === 'html') {
    return (
      <div style={style || { position: 'absolute', top: -12, right: 30, paddingTop: 4 }}>
        {fullyActive && renderButton()}
      </div>
    );
  }

  return (
    <InputAdornment position="end" style={{ position: 'absolute', right: 0 }}>
      {fullyActive && renderButton()}
    </InputAdornment>
  );
};

export default TextFieldAskAI;
