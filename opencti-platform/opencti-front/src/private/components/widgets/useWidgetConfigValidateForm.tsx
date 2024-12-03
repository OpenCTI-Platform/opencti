import { useWidgetConfigContext } from './WidgetConfigContext';
import { getCurrentAvailableParameters } from '../../../utils/widget/widgetUtils';

const useWidgetConfigValidateForm = () => {
  const { context, config, step, fintelWidgets } = useWidgetConfigContext();
  const { type, parameters, dataSelection } = config.widget;

  const alreadyUsedVariables = (fintelWidgets ?? [])
    .filter((w) => w.variable_name !== config.fintelVariableName)
    .flatMap(({ widget, variable_name }) => {
      if (widget.type !== 'attribute') return variable_name;
      return (widget.dataSelection[0].columns ?? []).flatMap((c) => c.variableName ?? []);
    });

  const isDataSelectionAttributesValid = () => {
    for (const d of dataSelection) {
      if (d.attribute?.length === 0) return false;
    }
    return true;
  };

  const isVarNameAlreadyUsed = (varName?: string | null) => {
    return alreadyUsedVariables.includes(varName ?? '')
      || (config.widget.dataSelection[0].columns ?? []).filter((c) => c.variableName === varName).length > 1;
  };

  // Check we are at the last step
  const isLastStep = step === 3;
  // Check there is a type
  const isTypeOk = !!type && type !== '';
  // Check all data selections has an attribute if needed
  const isAttributeConfOk = !getCurrentAvailableParameters(type).includes('attribute')
    || (getCurrentAvailableParameters(type).includes('attribute') && isDataSelectionAttributesValid());
  // Check variable name is filled in case of fintel
  const isVariableNameOk = (
    (context !== 'fintelTemplate')
    || (context === 'fintelTemplate' && type === 'attribute')
    || (context === 'fintelTemplate' && !!config.fintelVariableName)
  );
  // Check title is filled in case of fintel
  const isTitleOk = (
    (context !== 'fintelTemplate')
    || (context === 'fintelTemplate' && !!parameters?.title)
  );
  // Check if the variable name is already used in an other widget
  const isWidgetVarNameAlreadyUsed = !!config.fintelVariableName && isVarNameAlreadyUsed(config.fintelVariableName);

  return {
    isFormValid: isLastStep && isAttributeConfOk && isVariableNameOk && isTitleOk && isTypeOk && !isWidgetVarNameAlreadyUsed,
    isWidgetVarNameAlreadyUsed,
    isVarNameAlreadyUsed,
  };
};

export default useWidgetConfigValidateForm;
