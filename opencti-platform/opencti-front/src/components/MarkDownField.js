import React from 'react';
import ReactMde from 'react-mde';
import { useField } from 'formik';
import * as Showdown from 'showdown';
import InputLabel from '@material-ui/core/InputLabel';
import FormHelperText from '@material-ui/core/FormHelperText';

const converter = new Showdown.Converter({
  tables: true,
  simplifiedAutoLink: true,
  strikethrough: true,
  tasklists: true,
});

const MarkDownField = (props) => {
  const {
    field: { name },
    onSubmit,
    label,
    style,
  } = props;
  const [selectedTab, setSelectedTab] = React.useState('write');
  const [field, meta, helpers] = useField(name);
  const onBlur = (event) => {
    helpers.setTouched(true);
    const { value } = event.target;
    if (typeof onSubmit === 'function' && value && value.length > 3) {
      onSubmit(name, value);
    }
  };
  return (
    <div style={style} onBlur={onBlur} className={meta.touched && meta.error ? 'error' : 'main'}>
      <InputLabel style={{ fontSize: 10, marginBottom: 10 }}>
        {label}
      </InputLabel>
      <ReactMde
        value={field.value}
        onChange={helpers.setValue}
        selectedTab={selectedTab}
        onTabChange={setSelectedTab}
        onBlur={onBlur}
        generateMarkdownPreview={(markdown) => Promise.resolve(converter.makeHtml(markdown))
        }
      />
      {meta.touched ? (
        <FormHelperText error={true}>{meta.error}</FormHelperText>
      ) : (
        ''
      )}
    </div>
  );
};

export default MarkDownField;
