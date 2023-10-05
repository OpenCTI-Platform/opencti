import { makeStyles } from '@mui/styles';
import { Field } from 'formik';
import { Label } from 'mdi-material-ui';
import { union } from 'ramda';
import React, { FunctionComponent, useState } from 'react';
import AutocompleteField from '../../../../components/AutocompleteField';
import { useFormatter } from '../../../../components/i18n';
import { fetchQuery } from '../../../../relay/environment';
import { LabelsQuerySearchQuery$data } from '../../settings/__generated__/LabelsQuerySearchQuery.graphql';
import { LabelCreationContextualMutation$data } from '../../settings/labels/__generated__/LabelCreationContextualMutation.graphql';
import LabelCreation from '../../settings/labels/LabelCreation';
import { labelsSearchQuery } from '../../settings/LabelsQuery';
import { Option } from './ReferenceField';
import ItemIcon from '../../../../components/ItemIcon';

const useStyles = makeStyles({
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
});

interface ObjectLabelFieldProps {
  style: React.CSSProperties;
  name: string;
  helpertext?: string;
  dryrun?: boolean;
  setFieldValue?: (name: string, value: Option[]) => void;
  values?: Option[];
  onChange?: (name: string, value: Option[]) => void;
}

const ObjectLabelField: FunctionComponent<ObjectLabelFieldProps> = ({
  style,
  name,
  helpertext,
  dryrun = false,
  setFieldValue,
  values,
  onChange,
}) => {
  const classes = useStyles();
  const { t } = useFormatter();

  const [labelCreation, setLabelCreation] = useState(false);
  const [labels, setLabels] = useState<Option[]>([]);
  const [labelInput, setLabelInput] = useState('');

  const searchLabels = (event: React.ChangeEvent<HTMLInputElement>) => {
    setLabelInput(event?.target?.value ? event.target.value : '');
    fetchQuery(labelsSearchQuery, {
      search: event?.target?.value ? event.target.value : '',
    })
      .toPromise()
      .then((data) => {
        const newLabels = (
          (data as LabelsQuerySearchQuery$data).labels?.edges ?? []
        ).map(
          ({ node }) => ({
            label: node.value,
            value: node.id,
            color: node.color,
          }) as Option,
        );
        setLabels(union(labels, newLabels));
      });
  };

  return (
    <>
      <Field
        component={AutocompleteField}
        style={style}
        name={name}
        multiple={true}
        textfieldprops={{
          variant: 'standard',
          label: t('Labels'),
          helperText: helpertext,
          onFocus: searchLabels,
        }}
        noOptionsText={t('No available options')}
        options={labels}
        onInputChange={searchLabels}
        openCreate={() => setLabelCreation(true)}
        onChange={onChange}
        renderOption={(
          props: React.HTMLAttributes<HTMLLIElement>,
          option: Option,
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
        inputValue={labelInput}
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
