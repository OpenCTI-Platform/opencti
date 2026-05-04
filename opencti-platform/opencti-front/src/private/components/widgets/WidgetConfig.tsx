import React, { FunctionComponent } from 'react';
import { v4 as uuid } from 'uuid';
import type { Widget, WidgetContext } from '../../../utils/widget/widget';
import WidgetUpsert from './WidgetUpsert';
import { WidgetConfigProvider, WidgetConfigType } from './WidgetConfigContext';

interface WidgetConfigProps {
  onComplete: (value: Widget, variableName?: string) => void;
  open: boolean;
  onClose: () => void;
  widget?: Widget;
  context: WidgetContext;
  initialVariableName?: string;
  disabledSteps?: number[];
}

const WidgetConfig: FunctionComponent<WidgetConfigProps> = ({
  onComplete,
  widget,
  onClose,
  open,
  context,
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
      context={context}
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
