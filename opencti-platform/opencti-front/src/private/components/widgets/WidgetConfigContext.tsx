import React, { createContext, Dispatch, ReactNode, useContext, useEffect, useState } from 'react';
import type { Widget, WidgetHost, WidgetDataSelection, WidgetParameters, WidgetPerspective } from '../../../utils/widget/widget';
import { emptyFilterGroup, SELF_ID } from '../../../utils/filters/filtersUtils';
import { getCurrentDataSelectionLimit } from '../../../utils/widget/widgetUtils';
import type { WidgetVisualizationTypes } from '../../../utils/widget/widgetUtils';
import { applyBreakdownCompatibility, type WidgetBreakdownState } from '../../../utils/widget/widgetBreakdown';
import useResolvedWidgetBreakdown from './useResolvedWidgetBreakdown';

export interface WidgetConfigType {
  fintelVariableName: string | null;
  widget: {
    type: WidgetVisualizationTypes | '';
    perspective: WidgetPerspective | null;
    dataSelection: WidgetDataSelection[];
    parameters: WidgetParameters;
  };
}

interface WidgetConfigContextProps {
  host: WidgetHost;
  disabledSteps: number[];
  step: number;
  setStep: Dispatch<React.SetStateAction<number>>;
  config: WidgetConfigType;
  setConfigWidget: (widget: WidgetConfigType['widget']) => void;
  setConfigVariableName: (
    variableName: WidgetConfigType['fintelVariableName'],
  ) => void;
  setDataSelection: (dataSelection: WidgetDataSelection[]) => void;
  setDataSelectionWithIndex: (
    selection: WidgetDataSelection,
    index: number,
  ) => void;
  // Breakdown of the edited widget, derived once for every step
  breakdown: WidgetBreakdownState;
  // The config to submit, its breakdown dropped if the widget can no longer be broken down by it
  getSubmittedConfig: () => WidgetConfigType;
}

const WidgetConfigContext = createContext<WidgetConfigContextProps | undefined>(undefined);

interface WidgetConfigProviderProps {
  children: ReactNode;
  host: WidgetHost;
  disabledSteps: number[];
  initialWidget: Widget | undefined;
  initialVariableName: string | undefined;
  open: boolean;
}

const buildConfig = (
  context: WidgetHost,
  w?: Widget,
  varName?: string,
): WidgetConfigType => {
  let type = w?.type ?? '';
  if (type === '' && context.kind === 'fintelTemplate') {
    type = 'list';
  }

  return {
    fintelVariableName: varName ?? null,
    widget: {
      type: type as WidgetVisualizationTypes | '',
      perspective: w?.perspective ?? null,
      parameters: w?.parameters ?? {},
      dataSelection: w?.dataSelection ?? [{
        label: '',
        number: 10,
        sort_by: 'created_at',
        sort_mode: 'desc',
        attribute: 'entity_type',
        date_attribute: 'created_at',
        perspective: null,
        isTo: true,
        filters: emptyFilterGroup,
        dynamicFrom: emptyFilterGroup,
        dynamicTo: emptyFilterGroup,
        instance_id: (w?.type === 'attribute' || w?.type === 'custom-attributes') ? SELF_ID : undefined,
      }],
    },
  };
};

export const WidgetConfigProvider = ({
  children,
  host,
  initialWidget,
  initialVariableName,
  open,
  disabledSteps,
}: WidgetConfigProviderProps) => {
  const [conf, setConfig] = useState(buildConfig(host, undefined, undefined));
  const [step, setStep] = useState(0);

  const reset = () => {
    setConfig(buildConfig(host, undefined, undefined));
    setStep(0);
  };

  const init = () => {
    setConfig(buildConfig(host, initialWidget, initialVariableName));
    let initialStep = 0;
    if (initialWidget) {
      if (initialWidget?.type === 'text' || initialWidget?.type === 'attribute' || initialWidget?.type === 'custom-attributes') {
        initialStep = 3;
      } else if (initialWidget?.dataSelection) {
        initialStep = 2;
      }
    } else if (host.kind === 'fintelTemplate') {
      initialStep = 1;
    }
    setStep(initialStep);
  };

  useEffect(() => {
    if (open) init();
    else reset();
  }, [open]);

  const setConfigWidget = (widget: WidgetConfigType['widget']) => {
    // Check if widget type is changing and validate dataSelection
    let adjustedWidget = widget;

    if (widget.type && widget.type !== conf.widget.type) {
      const newLimit = getCurrentDataSelectionLimit(widget.type);

      // If there's a limit and current dataSelection exceeds it
      if (newLimit > 0 && conf.widget.dataSelection.length > newLimit) {
        adjustedWidget = {
          ...widget,
          dataSelection: conf.widget.dataSelection.slice(0, newLimit),
        };
      }
    }

    setConfig((oldConf) => ({
      ...oldConf,
      widget: {
        ...oldConf.widget,
        ...adjustedWidget,
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

  const breakdown = useResolvedWidgetBreakdown(conf.widget, host, open);
  // The breakdown is kept while the widget is edited, and only dropped on submit
  const getSubmittedConfig = () => ({ ...conf, widget: applyBreakdownCompatibility(conf.widget, breakdown) });

  return (
    <WidgetConfigContext.Provider value={{
      host,
      disabledSteps,
      config: conf,
      setConfigWidget,
      setConfigVariableName,
      setDataSelection,
      setDataSelectionWithIndex,
      step,
      setStep,
      breakdown,
      getSubmittedConfig,
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

/**
 * Breakdown of the edited widget: whether its controls show, the fields offered, whether the saved filter
 * of its dataset is read, and the field the widget keeps on submit.
 */
export const useWidgetBreakdownState = () => useWidgetConfigContext().breakdown;
