import { useWidgetConfigContext } from './WidgetConfigContext';
import { getCurrentAvailableParameters } from '../../../utils/widget/widgetUtils';

const useWidgetConfigValidateForm = () => {
  const { context, config, step } = useWidgetConfigContext();
  const { type, parameters, dataSelection } = config.widget;

  const isDataSelectionAttributesValid = () => {
    for (const d of dataSelection) {
      if (d.attribute?.length === 0) return false;
    }
    return true;
  };

  // Check we are at the last step
  const isLastStep = step === 3;
  // Check there is a type
  const isTypeOk = !!type && type !== '';
  // Check all data selections has an attribute if needed
  const isAttributeConfOk = !getCurrentAvailableParameters(type).includes('attribute')
    || (getCurrentAvailableParameters(type).includes('attribute') && isDataSelectionAttributesValid());
  // Check variable name is filled in case of fintel
  const isVariableNameOk = context === 'fintelTemplate' && !!config.fintelVariableName;
  // Check title is filled in case of fintel
  const isTitleOk = context === 'fintelTemplate' && !!parameters?.title;

  return isLastStep && isAttributeConfOk && isVariableNameOk && isTitleOk && isTypeOk;
};

export default useWidgetConfigValidateForm;
