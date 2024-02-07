import React, { FunctionComponent, useState } from 'react';
import { AutoAwesomeOutlined } from '@mui/icons-material';
import EETooltip from '@components/common/entreprise_edition/EETooltip';
import MenuItem from '@mui/material/MenuItem';
import Menu from '@mui/material/Menu';
import { v4 as uuid } from 'uuid';
import { graphql, useMutation } from 'react-relay';
import ToggleButton from '@mui/material/ToggleButton';
import { PopoverProps } from '@mui/material/Popover';
import { useFormatter } from '../../../../components/i18n';
import ResponseDialog from '../../../../utils/ai/ResponseDialog';
import useEnterpriseEdition from '../../../../utils/hooks/useEnterpriseEdition';

// region types
interface StixCoreObjectAskAiProps {
  instanceId: string;
  type: 'container' | 'threat' | 'victim';
  onChange: (value: string) => void;
  format: 'text' | 'html' | 'markdown'
}

const stixCoreObjectAskAIContainerReportMutation = graphql`
  mutation StixCoreObjectAskAIContainerReportMutation($id: ID!, $containerId: String!, $paragraphs: Int, $tone: Tone, $format: Format) {
    aiContainerGenerateReport(id: $id, containerId: $containerId, paragraphs: $paragraphs, tone: $tone, format: $format)
  }
`;

const StixCoreObjectAskAI: FunctionComponent<StixCoreObjectAskAiProps> = ({ instanceId, type, onChange, format = 'html' }) => {
  const { t_i18n } = useFormatter();
  const isEnterpriseEdition = useEnterpriseEdition();
  const [disableResponse, setDisableResponse] = useState(false);
  const [menuOpen, setMenuOpen] = useState<{ open: boolean; anchorEl: PopoverProps['anchorEl'] }>({ open: false, anchorEl: null });
  const [busId, setBusId] = useState<string | null>(null);
  const [displayAskAI, setDisplayAskAI] = useState(false);
  const handleOpenMenu = (event: React.SyntheticEvent) => {
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
  const [commitMutation] = useMutation(stixCoreObjectAskAIContainerReportMutation);
  const handleAskAi = (action: string) => {
    setDisableResponse(true);
    handleCloseMenu();
    const id = uuid();
    setBusId(id);
    handleOpenAskAI();
    switch (action) {
      case 'container-report':
        commitMutation({
          variables: {
            id,
            containerId: instanceId,
            paragraphs: 10,
            tone: 'technical',
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
    <>
      <EETooltip title={t_i18n('Ask AI')}>
        <ToggleButton
          onClick={handleOpenMenu}
          value="ask-ai"
          size="small"
          style={{ marginRight: 3 }}
        >
          <AutoAwesomeOutlined fontSize="small" color="secondary" />
        </ToggleButton>
      </EETooltip>
      <Menu
        id="menu-appbar"
        anchorEl={menuOpen.anchorEl}
        open={menuOpen.open}
        onClose={handleCloseMenu}
      >
        {type === 'container' && (
          <MenuItem onClick={() => handleAskAi('container-report')}>
            {t_i18n('Generate report document')}
          </MenuItem>
        )}
      </Menu>
      {busId && (
        <ResponseDialog
          id={busId}
          isDisabled={disableResponse}
          isOpen={displayAskAI}
          handleClose={handleCloseAskAI}
          handleAccept={(value) => {
            onChange(value);
            handleCloseAskAI();
          }}
          handleFollowUp={handleCloseAskAI}
          followUpActions={[{ key: 'retry', label: t_i18n('Retry') }]}
          format={format}
        />
      )}
    </>
  );
};

export default StixCoreObjectAskAI;
