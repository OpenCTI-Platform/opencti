import { makeStyles } from '@mui/styles';
import { Field } from 'formik';
import React, { FunctionComponent, useState } from 'react';
import AutocompleteField from '../../../../components/AutocompleteField';
import { useFormatter } from '../../../../components/i18n';
import { fetchQuery } from '../../../../relay/environment';
import { LabelsQuerySearchQuery$data } from '../../settings/__generated__/LabelsQuerySearchQuery.graphql';
import { LabelCreationContextualMutation$data } from '../../settings/labels/__generated__/LabelCreationContextualMutation.graphql';
import LabelCreation from '../../settings/labels/LabelCreation';
import { labelsSearchQuery } from '../../settings/LabelsQuery';
import ItemIcon from '../../../../components/ItemIcon';
import { FieldOption } from '../../../../utils/field';

// Deprecated - https://mui.com/system/styles/basics/
// Do not use it for new code.
const useStyles = makeStyles({
  icon: {
    paddingTop: 4,
    display: 'inline-block',
  },
  text: {
    display: 'inline-block',
    flexGrow: 1,
    marginInlineStart: 10,
  },
  autoCompleteIndicator: {
    display: 'none',
  },
});

interface ObjectLabelFieldProps {
  style?: React.CSSProperties;
  name: string;
  helpertext?: string;
  dryrun?: boolean;
  required?: boolean;
  setFieldValue?: (name: string, value: FieldOption[]) => void;
  values?: FieldOption[];
  onChange?: (name: string, value: FieldOption[]) => void;
  disabled?: boolean;
}

const ObjectLabelField: FunctionComponent<ObjectLabelFieldProps> = ({
  style,
  name,
  helpertext,
  dryrun = false,
  required = false,
  setFieldValue,
  values,
  onChange,
  disabled,
}) => {
  const classes = useStyles();
  const { t_i18n } = useFormatter();

  const [labelCreation, setLabelCreation] = useState(false);
  const [labels, setLabels] = useState<FieldOption[]>([]);
  const [labelInput, setLabelInput] = useState('');

  const searchLabels = async (event: React.ChangeEvent<HTMLInputElement>) => {
    setLabelInput(event?.target?.value ? event.target.value : '');

    const data = await fetchQuery(labelsSearchQuery, {
      search: event?.target?.value ? event.target.value : '',
      orderBy: 'value',
      orderMode: 'asc',
    }).toPromise();

    const edges = (data as LabelsQuerySearchQuery$data)?.labels?.edges ?? [];
    const labelOptions = edges.map((n) => {
      return {
        label: n.node.value,
        value: n.node.id,
        color: n.node.color,
      } as FieldOption;
    });

    setLabels(labelOptions);
  };

  return (
    <>
      <Field
        component={AutocompleteField}
        disabled={disabled}
        style={style}
        name={name}
        required={required}
        multiple={true}
        textfieldprops={{
          variant: 'standard',
          label: t_i18n('Labels'),
          helperText: helpertext,
          onFocus: searchLabels,
        }}
        noOptionsText={t_i18n('No available options')}
        options={labels}
        onInputChange={searchLabels}
        openCreate={() => setLabelCreation(true)}
        onChange={onChange}
        renderOption={(
          props: React.HTMLAttributes<HTMLLIElement>,
          option: FieldOption,
        ) => (
          <li {...props}>
            <div className={classes.icon} style={{ color: option.color }}>
              <ItemIcon type="Label" color={option.color} />
            </div>
            <div className={classes.text}>{option.label}</div>
          </li>
        )}
        classes={{ clearIndicator: classes.autoCompleteIndicator }}
      />
      <LabelCreation
        contextual={true}
        inputValueContextual={labelInput}
        required={required}
        open={labelCreation}
        handleClose={() => setLabelCreation(false)}
        dryrun={dryrun}
        creationCallback={(data: LabelCreationContextualMutation$data) => {
          if (data.labelAdd) {
            setFieldValue?.(name, [
              ...(values ?? []),
              { label: data.labelAdd.value ?? '', value: data.labelAdd.id },
            ]);
          }
        }}
      />
    </>
  );
};

export default ObjectLabelField;
