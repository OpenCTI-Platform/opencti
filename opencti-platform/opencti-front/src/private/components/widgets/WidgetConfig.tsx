import React, { FunctionComponent } from 'react';
import { v4 as uuid } from 'uuid';
import type { Widget, WidgetHost } from '../../../utils/widget/widget';
import WidgetUpsert from './WidgetUpsert';
import { WidgetConfigProvider, WidgetConfigType } from './WidgetConfigContext';

interface WidgetConfigProps {
  onComplete: (value: Widget, variableName?: string) => void;
  open: boolean;
  onClose: () => void;
  widget?: Widget;
  host: WidgetHost;
  initialVariableName?: string;
  disabledSteps?: number[];
}

const WidgetConfig: FunctionComponent<WidgetConfigProps> = ({
  onComplete,
  widget,
  onClose,
  open,
  host,
  initialVariableName,
  disabledSteps,
}) => {
  const close = () => onClose();

  const onSubmit = (newConfig: WidgetConfigType) => {
    onComplete(
      {
        ...(widget ?? {}),
        id: widget?.id ?? uuid(),
        ...newConfig.widget,
      },
      newConfig.fintelVariableName ?? undefined,
    );
    close();
  };

  return (
    <WidgetConfigProvider
      initialWidget={widget}
      initialVariableName={initialVariableName}
      host={host}
      disabledSteps={disabledSteps ?? []}
      open={open}
    >
      <WidgetUpsert
        open={open}
        onCancel={close}
        onSubmit={onSubmit}
        isUpdate={!!widget}
      />
    </WidgetConfigProvider>
  );
};

export default WidgetConfig;
