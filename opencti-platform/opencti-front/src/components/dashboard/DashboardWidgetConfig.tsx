import React, { useRef, useState } from 'react';
import Button from '@common/button/Button';
import MenuItem from '@mui/material/MenuItem';
import VisuallyHiddenInput from '../../private/components/common/VisuallyHiddenInput';
import WidgetConfig from '../../private/components/widgets/WidgetConfig';
import { useFormatter } from '../i18n';
import type { Widget } from '../../utils/widget/widget';

type WorkspaceWidgetConfigProps = {
  handleImportWidget: (widgetFile: File) => void;
  widget?: Widget;
  onComplete: (value: Widget, variableName?: string) => void;
  closeMenu?: () => void;
};

const DashboardWidgetConfig = ({ widget, onComplete, closeMenu, handleImportWidget }: WorkspaceWidgetConfigProps) => {
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
          <Button
            variant="secondary"
            disableElevation
            onClick={handleImportWidgetButtonClick}
          >
            {t_i18n('Import Widget')}
          </Button>
          <Button
            variant="secondary"
            disableElevation
            onClick={handleOpenWidgetConfig}
            data-testid="create-widget-button"
          >
            {t_i18n('Create Widget')}
          </Button>
        </>
      )}
      {widget && (
        <MenuItem onClick={handleUpdateWidgetMenuClick}>
          {t_i18n('Update')}
        </MenuItem>
      )}
      <WidgetConfig
        onComplete={(widget, variableName) => onComplete(widget, variableName)}
        widget={widget}
        onClose={handleCloseWidgetConfig}
        open={isWidgetConfigOpen}
        context="workspace"
      />
    </>
  );
};

export default DashboardWidgetConfig;
