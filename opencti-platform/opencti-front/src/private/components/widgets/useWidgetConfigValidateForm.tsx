import { useWidgetConfigContext } from './WidgetConfigContext';
import { checkIfDateAttributeValid, getCurrentAvailableParameters, isDataSelectionNumberValid } from '../../../utils/widget/widgetUtils';

export const fintelTemplateVariableNameChecker = /^[A-Za-z0-9_-]+$/;

const useWidgetConfigValidateForm = () => {
  const { host, config, step } = useWidgetConfigContext();
  const { type, parameters, dataSelection } = config.widget;

  const alreadyUsedVariables = (host.kind === 'fintelTemplate' ? host.fintelWidgets : [])
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

  // ======================
  // === List of checks ===
  // ======================

  // Check we are at the last step
  const isLastStep = step === 3;
  // Check there is a type
  const isTypeFilled = !!type;

  // Check the number of results is lower than 100 for lists
  const isDataSelectionNumberCheck = isDataSelectionNumberValid(type, dataSelection);
  // Check all data selections has an attribute filled if  widget type requires it
  const isDataSelectionAttributesFilled = !getCurrentAvailableParameters(type).includes('attribute')
    || (getCurrentAvailableParameters(type).includes('attribute') && isDataSelectionAttributesValid());

  // Check variable name is filled in case of fintel
  const needVariableName = host.kind === 'fintelTemplate' && type !== 'attribute';
  const isVariableNameFilled = !needVariableName || !!config.fintelVariableName;

  // Check variable name is valid in case of fintel
  const isVariableNameValid = (
    !config.fintelVariableName
    || fintelTemplateVariableNameChecker.test(config.fintelVariableName)
  );

  // Check date attribute is valid according to the widget perspective
  const isDateAttributeValid = checkIfDateAttributeValid(dataSelection);

  // Check title is filled in case of fintel
  const isTitleFilled = (
    (host.kind !== 'fintelTemplate')
    || (host.kind === 'fintelTemplate' && !!parameters?.title)
  );

  // Check if the variable name is already used in an other widget
  const isWidgetVarNameAlreadyUsed = !!config.fintelVariableName && isVarNameAlreadyUsed(config.fintelVariableName);

  // Check the incident or case of a timeline widget is selected (a custom view uses the entity it is displayed on)
  const isCaseTimelineContainerFilled = type !== 'case-timeline' || host.kind === 'custom-view' || !!parameters?.container_id;

  return {
    isFormValid: (
      isLastStep
      && isDataSelectionNumberCheck
      && isDataSelectionAttributesFilled
      && isVariableNameFilled
      && isVariableNameValid
      && isDateAttributeValid
      && isTitleFilled
      && isTypeFilled
      && !isWidgetVarNameAlreadyUsed
      && isCaseTimelineContainerFilled
    ),
    isWidgetVarNameAlreadyUsed,
    isVarNameAlreadyUsed,
    isVariableNameValid,
    isDateAttributeValid,
  };
};

export default useWidgetConfigValidateForm;
