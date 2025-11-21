import { Field } from 'formik';
import TextField from '../../../../../../components/TextField';
import { fieldSpacingContainerStyle } from '../../../../../../utils/field';

interface PlaybookFlowFieldNumberProps {
  name: string
  label: string
}

const PlaybookFlowFieldNumber = ({
  name,
  label,
}: PlaybookFlowFieldNumberProps) => {
  return (
    <Field
      fullWidth
      variant="standard"
      type="number"
      name={name}
      label={label}
      component={TextField}
      style={fieldSpacingContainerStyle}
    />
  );
};

export default PlaybookFlowFieldNumber;
