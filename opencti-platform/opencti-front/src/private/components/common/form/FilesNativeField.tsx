import React, { FunctionComponent, useState } from 'react';
import { graphql } from 'react-relay';
import {
  Combobox,
  type ComboboxChangeMeta,
  ComboboxChips,
  ComboboxContent,
  ComboboxControls,
  ComboboxField,
  ComboboxHelperText,
  ComboboxInput,
  ComboboxLabel,
  ComboboxTrigger,
} from '@filigran/design-system';
import { FilesNativeFieldQuery$data } from '@components/common/form/__generated__/FilesNativeFieldQuery.graphql';
import makeStyles from '@mui/styles/makeStyles';
import { FileOutline } from 'mdi-material-ui';
import { fetchQuery } from '../../../../relay/environment';
import { truncate } from '../../../../utils/String';

interface FilesFieldProps {
  stixCoreObjectId: string;
  name: string;
  label: string;
  currentValue: { label: string; value: string }[];
  onChange?: (value: { label: string; value: string }[] | null) => void;
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
      <Combobox<{ label: string; value: string }>
        selectOnFocus={true}
        multiple={true}
        // MUI parity: none of these mounts passed disableCloseOnSelect, so the panel closed
        // after each pick.
        closeOnSelect
        value={currentValue}
        // Truncation lives in the label function here, so it already applied to BOTH the chips
        // and the input under MUI — unlike the fields whose renderTags used a different label.
        getOptionLabel={(option) => truncate(option?.label ?? '', 40)}
        // MUI hid its clear indicator with display:none; the library defaults
        // clearable to true, so the affordance must be declined explicitly.
        clearable={false}
        options={files}
        // searchFiles takes no argument — it loads every file of the entity — so
        // the cause gate only avoids redundant fetches.
        onInputChange={(_search: string, meta: ComboboxChangeMeta) => {
          if (meta.cause === 'type') searchFiles();
        }}
        onValueChange={(value) => (onChange ? onChange(value as { label: string; value: string }[]) : null)}
        renderOption={(option) => (
          <>
            <div className={classes.icon}>
              <FileOutline />
            </div>
            <div className={classes.text}>{option.label ?? ''}</div>
          </>
        )}
      >
        <div style={containerStyle}>
          <ComboboxLabel>{label}</ComboboxLabel>
          <ComboboxField>
            <ComboboxChips aria-label={label} />
            <ComboboxInput name={name} onFocus={() => searchFiles()} />
            <ComboboxControls>
              <ComboboxTrigger />
            </ComboboxControls>
          </ComboboxField>
          {helperText && <ComboboxHelperText>{helperText}</ComboboxHelperText>}
        </div>
        <ComboboxContent listAriaLabel={label} />
      </Combobox>
    </div>
  );
};

export default FilesNativeField;
