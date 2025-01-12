import React, { FunctionComponent } from 'react';
import { v4 as uuid } from 'uuid';
import WidgetUpsert from './WidgetUpsert';
import { WidgetConfigProvider, WidgetConfigType } from './WidgetConfigContext';
import type { Widget, WidgetContext } from '../../../utils/widget/widget';

interface WidgetConfigProps {
  onComplete: (value: Widget, variableName?: string) => void,
  open: boolean,
  setOpen: (open: boolean) => void,
  widget?: Widget,
  context: WidgetContext,
  initialVariableName?: string,
}

const WidgetConfig: FunctionComponent<WidgetConfigProps> = ({
  onComplete,
  widget,
  setOpen,
  open,
  context,
  initialVariableName,
}) => {
  const close = () => {
    setOpen(false);
  };

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
      open={open}
    >
      <WidgetUpsert
        open={open}
        onCancel={close}
        onSubmit={onSubmit}
      />
    </WidgetConfigProvider>
  );
};

export default WidgetConfig;
