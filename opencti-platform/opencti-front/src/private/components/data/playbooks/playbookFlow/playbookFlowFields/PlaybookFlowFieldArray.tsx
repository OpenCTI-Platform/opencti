import { MenuItem, Tooltip, TooltipProps } from '@mui/material';
import { Field, useFormikContext } from 'formik';
import AutocompleteField from '../../../../../../components/AutocompleteField';
import { fieldSpacingContainerStyle } from '../../../../../../utils/field';
import useEntityTranslation from '../../../../../../utils/hooks/useEntityTranslation';

interface Option {
  const: string
  title: string
}

interface PlaybookFlowFieldArrayProps {
  name: string
  label: string
  options: Option[]
  multiple?: boolean
}

const PlaybookFlowFieldArray = ({
  name,
  label,
  options,
  multiple = false,
}: PlaybookFlowFieldArrayProps) => {
  const { translateEntityType } = useEntityTranslation();
  const { setFieldValue } = useFormikContext();

  const setOneOfValue = (value: Option) => {
    setFieldValue(name, value.const);
  };

  const setMultipleValue = (values: Option[]) => {
    setFieldValue(name, values.map((o) => (o.const)));
  };

  return (
    <Field
      fullWidth
      multiple={multiple}
      component={AutocompleteField}
      style={fieldSpacingContainerStyle}
      textfieldprops={{
        variant: 'standard',
        label,
      }}
      name={name}
      options={options}
      onInternalChange={(_: string, option: Option | Option[]) => {
        if (Array.isArray(option)) {
          setMultipleValue(option);
        } else {
          setOneOfValue(option);
        }
      }}
      isOptionEqualToValue={(option: Option, value: string) => {
        return option.const === value;
      }}
      renderOption={(props: TooltipProps, value: Option) => (
        <Tooltip
          {...props}
          key={value.const}
          title={value.title}
          placement="bottom-start"
        >
          <MenuItem value={value.const}>
            {/* value might be an entity type, we try to translate it */}
            {translateEntityType(value.title)}
          </MenuItem>
        </Tooltip>
      )}
      getOptionLabel={(option: Option) => {
        return translateEntityType(option.title ?? option);
      }}
    />
  );
};

export default PlaybookFlowFieldArray;
