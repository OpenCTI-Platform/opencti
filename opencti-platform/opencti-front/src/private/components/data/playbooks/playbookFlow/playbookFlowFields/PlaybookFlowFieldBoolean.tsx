import { Field } from 'formik';
import SwitchField from '../../../../../../components/fields/SwitchField';
import { fieldSpacingContainerStyle } from '../../../../../../utils/field';

interface PlaybookFlowFieldBooleanProps {
  name: string
  label: string
}

const PlaybookFlowFieldBoolean = ({
  name,
  label,
}: PlaybookFlowFieldBooleanProps) => {
  return (
    <Field
      type="checkbox"
      name={name}
      label={label}
      component={SwitchField}
      containerstyle={fieldSpacingContainerStyle}
    />
  );
};

export default PlaybookFlowFieldBoolean;
