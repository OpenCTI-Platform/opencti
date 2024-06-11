import React, { FunctionComponent, useState } from 'react';
import { graphql } from 'react-relay';
import Autocomplete from '@mui/material/Autocomplete';
import TextField from '@mui/material/TextField';
import { FilesNativeFieldQuery$data } from '@components/common/form/__generated__/FilesNativeFieldQuery.graphql';
import makeStyles from '@mui/styles/makeStyles';
import { FileOutline } from 'mdi-material-ui';
import { fetchQuery } from '../../../../relay/environment';
import { truncate } from '../../../../utils/String';

interface FilesFieldProps {
  stixCoreObjectId: string;
  name: string;
  label: string;
  currentValue: { label: string, value: string }[];
  onChange?: (value: { label: string, value: string }[] | null) => void;
  containerStyle?: Record<string, string | number>;
  helperText?: string;
}

// Deprecated - https://mui.com/system/styles/basics/
// Do not use it for new code.
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
      externalReferences {
        edges {
          node {
            id
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
      }
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
  helperText,
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
        const importFiles = (
          (data as FilesNativeFieldQuery$data)?.stixCoreObject?.importFiles?.edges ?? []
        ).map((n) => ({
          label: n?.node.name ?? '',
          value: n?.node.id ?? '',
        }));
        const externalReferencesFiles = (
          (data as FilesNativeFieldQuery$data)?.stixCoreObject?.externalReferences?.edges ?? []
        ).flatMap(({ node }) => node?.importFiles?.edges ?? []).map((n) => ({
          label: n?.node.name ?? '',
          value: n?.node.id ?? '',
        }));
        const allFiles = [...importFiles, ...externalReferencesFiles];
        // Keep only the unique list of options
        const uniqFiles = allFiles.filter((item, index) => {
          return (
            allFiles.findIndex((e) => e.value === item.value) === index
          );
        });
        setFiles(uniqFiles);
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
            helperText={helperText}
          />
        )}
        renderOption={(
          props: React.HTMLAttributes<HTMLLIElement>,
          option: { label: string, value: string },
        ) => (
          <li {...props}>
            <div className={classes.icon}>
              <FileOutline />
            </div>
            <div className={classes.text}>{option.label ?? ''}</div>
          </li>
        )}
        classes={{ clearIndicator: classes.autoCompleteIndicator }}
        options={files}
        onFocus={searchFiles}
        onInputChange={searchFiles}
        onChange={(_, value) => (onChange ? onChange(value) : null)}
      />
    </div>
  );
};

export default FilesNativeField;
