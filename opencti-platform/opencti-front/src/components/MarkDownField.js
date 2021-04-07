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
    form: { setFieldValue, setTouched },
    field: { name },
    onFocus,
    onSubmit,
    label,
    style,
  } = props;
  const [selectedTab, setSelectedTab] = React.useState('write');
  const [field, meta] = useField(name);
  const internalOnFocus = React.useCallback(() => {
    if (typeof onFocus === 'function') {
      onFocus(name);
    }
  }, [onFocus, name]);
  const internalOnBlur = React.useCallback(
    (event) => {
      const { value } = event.target;
      setTouched(true);
      if (typeof onSubmit === 'function') {
        onSubmit(name, value || '');
      }
    },
    [onSubmit, setTouched, name],
  );
  return (
    <div
      style={style}
      className={meta.touched && meta.error ? 'error' : 'main'}
    >
      <InputLabel style={{ fontSize: 10, marginBottom: 10 }}>
        {label}
      </InputLabel>
      <ReactMde
        value={field.value}
        onChange={(value) => setFieldValue(name, value)}
        selectedTab={selectedTab}
        onTabChange={setSelectedTab}
        generateMarkdownPreview={(markdown) => Promise.resolve(converter.makeHtml(markdown))
        }
        childProps={{
          textArea: {
            onBlur: internalOnBlur,
            onFocus: internalOnFocus,
          },
        }}
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
