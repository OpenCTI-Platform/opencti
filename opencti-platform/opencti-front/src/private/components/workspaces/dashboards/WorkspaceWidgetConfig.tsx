import React, { useRef, useState } from 'react';
import Button from '@common/button/Button';
import MenuItem from '@mui/material/MenuItem';
import { Widget } from 'src/utils/widget/widget';
import VisuallyHiddenInput from '../../common/VisuallyHiddenInput';
import WidgetConfig from '../../widgets/WidgetConfig';
import Security from '../../../../utils/Security';
import { EXPLORE_EXUPDATE } from '../../../../utils/hooks/useGranted';
import { useFormatter } from '../../../../components/i18n';

type WorkspaceWidgetConfigProps = {
  handleImportWidget: (widgetFile: File) => void;
  widget?: Widget;
  onComplete: (value: Widget, variableName?: string) => void;
  closeMenu?: () => void;
};

const WorkspaceWidgetConfig = ({ widget, onComplete, closeMenu, handleImportWidget }: WorkspaceWidgetConfigProps) => {
  const { t_i18n } = useFormatter();
  const [isWidgetConfigOpen, setIsWidgetConfigOpen] = useState<boolean>(false);
  const inputRef: React.MutableRefObject<HTMLInputElement | null> = useRef(null);

  const handleWidgetImport = async (event: React.ChangeEvent<HTMLInputElement>) => {
    const importedWidgetConfiguration = event.target.files?.[0];
    if (importedWidgetConfiguration) handleImportWidget(importedWidgetConfiguration);
    if (inputRef.current) inputRef.current.value = ''; // Reset the input uploader ref
  };

  const handleOpenWidgetConfig = () => setIsWidgetConfigOpen(true);
  const handleCloseWidgetConfig = () => setIsWidgetConfigOpen(false);

  const handleUpdateWidgetMenuClick = () => {
    closeMenu?.();
    handleOpenWidgetConfig();
  };

  const handleImportWidgetButtonClick = () => inputRef.current?.click();

  return (
    <>
      {!widget && (
        <>
          <VisuallyHiddenInput
            type="file"
            accept="application/JSON"
            ref={inputRef}
            onChange={handleWidgetImport}
          />
          <Security needs={[EXPLORE_EXUPDATE]}>
            <>
              <Button
                variant="secondary"
                disableElevation
                sx={{ marginLeft: 1 }}
                onClick={handleImportWidgetButtonClick}
              >
                {t_i18n('Import Widget')}
              </Button>
              <Button
                variant="secondary"
                disableElevation
                sx={{ marginLeft: 1 }}
                onClick={handleOpenWidgetConfig}
                data-testid="create-widget-button"
              >
                {t_i18n('Create Widget')}
              </Button>
            </>
          </Security>
        </>
      )}
      {widget && (
        <MenuItem onClick={handleUpdateWidgetMenuClick}>
          {t_i18n('Update')}
        </MenuItem>
      )}
      <WidgetConfig
        onComplete={onComplete}
        widget={widget}
        onClose={handleCloseWidgetConfig}
        open={isWidgetConfigOpen}
        context="workspace"
      />
    </>
  );
};

export default WorkspaceWidgetConfig;
