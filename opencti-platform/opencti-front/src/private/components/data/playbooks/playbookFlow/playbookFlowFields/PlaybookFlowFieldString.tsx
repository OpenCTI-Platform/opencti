import { Field } from 'formik';
import TextField from '../../../../../../components/TextField';
import { fieldSpacingContainerStyle } from '../../../../../../utils/field';

interface PlaybookFlowFieldStringProps {
  name: string
  label: string
}

const PlaybookFlowFieldString = ({
  name,
  label,
}: PlaybookFlowFieldStringProps) => {
  return (
    <Field
      fullWidth
      name={name}
      label={label}
      variant="standard"
      component={TextField}
      style={fieldSpacingContainerStyle}
    />
  );
};

export default PlaybookFlowFieldString;
