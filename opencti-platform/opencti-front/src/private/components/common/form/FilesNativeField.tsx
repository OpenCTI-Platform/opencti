import React, { FunctionComponent, useState } from 'react';
import { graphql } from 'react-relay';
import Autocomplete from '@mui/material/Autocomplete';
import TextField from '@mui/material/TextField';
import { FilesNativeFieldQuery$data } from '@components/common/form/__generated__/FilesNativeFieldQuery.graphql';
import makeStyles from '@mui/styles/makeStyles';
import { fetchQuery } from '../../../../relay/environment';
import { truncate } from '../../../../utils/String';
import ItemIcon from '../../../../components/ItemIcon';

interface FilesFieldProps {
  stixCoreObjectId: string;
  name: string;
  label: string;
  currentValue: { label: string, value: string }[];
  onChange?: (value: { label: string, value: string }[] | null) => void;
  containerStyle?: Record<string, string | number>;
}

const useStyles = makeStyles(() => ({
  icon: {
    paddingTop: 4,
    display: 'inline-block',
  },
  text: {
    display: 'inline-block',
    flexGrow: 1,
    marginLeft: 10,
  },
  autoCompleteIndicator: {
    display: 'none',
  },
}));

const filesNativeFieldQuery = graphql`
  query FilesNativeFieldQuery($id: String!) {
    stixCoreObject(id: $id) {
      importFiles {
        edges {
          node {
            id
            name
          }
        }
      }
    }
  }
`;

const FilesNativeField: FunctionComponent<FilesFieldProps> = ({
  stixCoreObjectId,
  label,
  name,
  containerStyle,
  currentValue,
  onChange,
}) => {
  const classes = useStyles();
  const [files, setFiles] = useState<{
    label: string;
    value: string;
  }[]
  >([]);
  const searchFiles = () => {
    fetchQuery(filesNativeFieldQuery, { id: stixCoreObjectId })
      .toPromise()
      .then((data) => {
        const newFiles = (
          (data as FilesNativeFieldQuery$data)?.stixCoreObject?.importFiles?.edges ?? []
        ).map((n) => ({
          label: n?.node.name ?? '',
          value: n?.node.id ?? '',
        }));
        const templateValues = [...files, ...newFiles];
        // Keep only the unique list of options
        const uniqTemplates = templateValues.filter((item, index) => {
          return (
            templateValues.findIndex((e) => e.value === item.value) === index
          );
        });
        setFiles(uniqTemplates);
      });
  };
  return (
    <div style={{ width: '100%' }}>
      <Autocomplete
        size="small"
        selectOnFocus={true}
        autoHighlight={true}
        handleHomeEndKeys={true}
        multiple={true}
        value={currentValue}
        getOptionLabel={(option) => truncate(option?.label ?? '', 40)}
        renderInput={({ inputProps: { value, ...inputProps }, ...params }) => (
          <TextField
            {...{ ...params, inputProps }}
            label={label}
            value={value}
            name={name}
            fullWidth={true}
            style={containerStyle}
          />
        )}
        renderOption={(
          props: React.HTMLAttributes<HTMLLIElement>,
          option: { label: string, value: string },
        ) => (
          <li {...props}>
            <div className={classes.icon}>
              <ItemIcon type="Country" />
            </div>
            <div className={classes.text}>{option.label ?? ''}</div>
          </li>
        )}
        classes={{ clearIndicator: classes.autoCompleteIndicator }}
        options={files}
        onInputChange={searchFiles}
        onChange={(_, value) => (onChange ? onChange(value) : null)}
      />
    </div>
  );
};

export default FilesNativeField;
