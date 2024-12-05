import React, { FunctionComponent, useState } from 'react';
import { Autocomplete, TextField, FormControl } from '@mui/material';
import makeStyles from '@mui/styles/makeStyles';
import { Option } from '@components/common/form/ReferenceField';

const useStyles = makeStyles(() => ({
  text: {
    display: 'inline-block',
    flexGrow: 1,
    marginLeft: 10,
  },
}));

interface PlatformFieldProps {
  id: string;
  label: string;
  onChange: (value: string[]) => void;
  containerStyle?: Record<string, string | number>;
  helpertext?: string;
  required?: boolean;
  value: string[];
}

const PlatformOptions = [
  { label: 'Windows', value: 'windows' },
  { label: 'Linux', value: 'linux' },
  { label: 'MacOS', value: 'macos' },
];

const PlatformField: FunctionComponent<PlatformFieldProps> = ({
  id,
  label,
  containerStyle,
  helpertext,
  onChange,
  value,
}) => {
  const classes = useStyles();
  const [platforms] = useState(PlatformOptions);

  const handleChange = (_event: any, newValue: Option[]) => {
    onChange(newValue.map((v) => v.value));
  };

  return (
    <FormControl style={{ width: '100%', ...containerStyle }} error={!!helpertext}>
      <Autocomplete
        id={id}
        multiple
        options={platforms}
        value={platforms.filter((platform) => value.includes(platform.value))}
        onChange={handleChange}
        getOptionLabel={(option) => option.label}
        renderInput={(params) => (
          <TextField
            {...params}
            label={label}
            variant="standard"
            helperText={helpertext}
          />
        )}
        renderOption={(props, option) => (
          <li {...props}>
            <div className={classes.text}>{option.label ?? ''}</div>
          </li>
        )}
      />
    </FormControl>
  );
};

export default PlatformField;
