import React, { createContext, Dispatch, ReactNode, useContext, useEffect, useState } from 'react';
import { FintelTemplateWidget } from '@components/settings/sub_types/fintel_templates/FintelTemplateWidgetsList';
import type { Widget, WidgetContext, WidgetDataSelection, WidgetParameters, WidgetPerspective } from '../../../utils/widget/widget';
import { emptyFilterGroup, SELF_ID } from '../../../utils/filters/filtersUtils';

export interface WidgetConfigType {
  fintelVariableName: string | null;
  widget: {
    type: string;
    perspective: WidgetPerspective | null;
    dataSelection: WidgetDataSelection[];
    parameters: WidgetParameters;
  };
}

interface WidgetConfigContextProps {
  context: WidgetContext;
  disabledSteps: number[];
  fintelWidgets?: FintelTemplateWidget[]
  fintelEntityType?: string
  fintelEditorValue?: string
  step: number;
  setStep: Dispatch<React.SetStateAction<number>>;
  config: WidgetConfigType;
  setConfigWidget: (widget: WidgetConfigType['widget']) => void;
  setConfigVariableName: (variableName: WidgetConfigType['fintelVariableName']) => void;
  setDataSelection: (dataSelection: WidgetDataSelection[]) => void;
  setDataSelectionWithIndex: (selection: WidgetDataSelection, index: number) => void;
}

const WidgetConfigContext = createContext<WidgetConfigContextProps | undefined>(undefined);

interface WidgetConfigProviderProps {
  children: ReactNode
  context: WidgetContext
  disabledSteps: number[]
  fintelWidgets: FintelTemplateWidget[] | undefined
  fintelEntityType: string | undefined
  fintelEditorValue: string | undefined
  initialWidget: Widget | undefined;
  initialVariableName: string | undefined;
  open: boolean;
}

const buildConfig = (
  context: WidgetContext,
  w?: Widget,
  varName?: string,
): WidgetConfigType => {
  let type = w?.type ?? '';
  if (type === '' && context === 'fintelTemplate') {
    type = 'list';
  }

  return {
    fintelVariableName: varName ?? null,
    widget: {
      type,
      perspective: w?.perspective ?? null,
      parameters: w?.parameters ?? {},
      dataSelection: w?.dataSelection ?? [{
        label: '',
        number: 10,
        sort_by: 'created_at',
        sort_mode: 'asc',
        attribute: 'entity_type',
        date_attribute: 'created_at',
        perspective: null,
        isTo: true,
        filters: emptyFilterGroup,
        dynamicFrom: emptyFilterGroup,
        dynamicTo: emptyFilterGroup,
        instance_id: w?.type === 'attribute' ? SELF_ID : undefined,
      }],
    },
  };
};

export const WidgetConfigProvider = ({
  children,
  context,
  initialWidget,
  initialVariableName,
  fintelWidgets,
  fintelEntityType,
  fintelEditorValue,
  open,
  disabledSteps,
}: WidgetConfigProviderProps) => {
  const [conf, setConfig] = useState(buildConfig(context, undefined, undefined));
  const [step, setStep] = useState(0);

  const reset = () => {
    setConfig(buildConfig(context, undefined, undefined));
    setStep(0);
  };

  const init = () => {
    setConfig(buildConfig(context, initialWidget, initialVariableName));
    let initialStep = 0;
    if (initialWidget) {
      if (initialWidget?.type === 'text' || initialWidget?.type === 'attribute') {
        initialStep = 3;
      } else if (initialWidget?.dataSelection) {
        initialStep = 2;
      }
    } else if (context === 'fintelTemplate') {
      initialStep = 1;
    }
    setStep(initialStep);
  };

  useEffect(() => {
    if (open) init();
    else reset();
  }, [open]);

  const setConfigWidget = (widget: WidgetConfigType['widget']) => {
    setConfig((oldConf) => ({
      ...oldConf,
      widget: {
        ...oldConf.widget,
        ...widget,
      },
    }));
  };

  const setDataSelection = (selection: WidgetDataSelection[]) => {
    setConfigWidget({ ...conf.widget, dataSelection: selection });
  };

  const setDataSelectionWithIndex = (data: WidgetDataSelection, index: number) => {
    setDataSelection([...conf.widget.dataSelection.map((d, i) => (i === index ? data : d))]);
  };

  const setConfigVariableName = (variableName: WidgetConfigType['fintelVariableName']) => {
    setConfig((oldConf) => ({
      ...oldConf,
      fintelVariableName: variableName,
    }));
  };

  return (
    <WidgetConfigContext.Provider value={{
      context,
      disabledSteps,
      fintelWidgets,
      fintelEntityType,
      fintelEditorValue,
      config: conf,
      setConfigWidget,
      setConfigVariableName,
      setDataSelection,
      setDataSelectionWithIndex,
      step,
      setStep,
    }}
    >
      {children}
    </WidgetConfigContext.Provider>
  );
};

export const useWidgetConfigContext = () => {
  const context = useContext(WidgetConfigContext);
  if (!context) throw Error('Hook used outside of WidgetConfigProvider');
  return context;
};
