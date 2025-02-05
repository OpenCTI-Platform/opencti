import React, { FunctionComponent } from 'react';
import { v4 as uuid } from 'uuid';
import { FintelTemplateWidget } from '@components/settings/sub_types/fintel_templates/FintelTemplateWidgetsList';
import type { Widget, WidgetContext } from '../../../utils/widget/widget';
import WidgetUpsert from './WidgetUpsert';
import { WidgetConfigProvider, WidgetConfigType } from './WidgetConfigContext';

interface WidgetConfigProps {
  onComplete: (value: Widget, variableName?: string) => void,
  open: boolean,
  setOpen: (open: boolean) => void,
  widget?: Widget,
  context: WidgetContext,
  initialVariableName?: string,
  disabledSteps?: number[]
  fintelWidgets?: FintelTemplateWidget[] // Used to avoid identical variable names.
  fintelEntityType?: string
  fintelEditorValue?: string
}

const WidgetConfig: FunctionComponent<WidgetConfigProps> = ({
  onComplete,
  widget,
  setOpen,
  open,
  context,
  initialVariableName,
  fintelWidgets,
  disabledSteps,
  fintelEntityType,
  fintelEditorValue,
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
      disabledSteps={disabledSteps ?? []}
      fintelWidgets={fintelWidgets}
      fintelEntityType={fintelEntityType}
      fintelEditorValue={fintelEditorValue}
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
