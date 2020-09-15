import React from 'react';
import ReactMde from 'react-mde';
import { useField } from 'formik';
import * as Showdown from 'showdown';
import InputLabel from '@material-ui/core/InputLabel';

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
  const [field, , helpers] = useField(name);
  const submit = (event) => {
    const { value } = event.target;
    if (typeof onSubmit === 'function' && value && value.length > 3) {
      onSubmit(name, value);
    }
  };
  return (
    <div style={style} onBlur={submit}>
      <InputLabel style={{ fontSize: 10, marginBottom: 10 }}>
        {label}
      </InputLabel>
      <ReactMde
        value={field.value}
        onChange={helpers.setValue}
        selectedTab={selectedTab}
        onTabChange={setSelectedTab}
        onBlur={submit}
        generateMarkdownPreview={(markdown) => Promise.resolve(converter.makeHtml(markdown))
        }
      />
    </div>
  );
};

export default MarkDownField;
