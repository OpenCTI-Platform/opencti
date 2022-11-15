import React, { FunctionComponent, useState } from 'react';
import { append } from 'ramda';
import { Field } from 'formik';
import { Label } from 'mdi-material-ui';
import makeStyles from '@mui/styles/makeStyles';
import { graphql } from 'react-relay';
import { fetchQuery } from '../../../../relay/environment';
import AutocompleteField from '../../../../components/AutocompleteField';
import StatusTemplateCreation from '../../settings/workflow/StatusTemplateCreation';
import { useFormatter } from '../../../../components/i18n';
import { StatusTemplateFieldSearchQuery$data } from './__generated__/StatusTemplateFieldSearchQuery.graphql';
import {
  StatusTemplateCreationContextualMutation$data,
} from '../../settings/workflow/__generated__/StatusTemplateCreationContextualMutation.graphql';

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

interface StatusTemplateFieldProps {
  name: string,
  setFieldValue: (field: string, value: (list: readonly { name: string; id: string; }[]) => { name: string; id: string; }[], shouldValidate?: boolean) => void,
  helpertext: string,
}

const StatusTemplateFieldQuery = graphql`
    query StatusTemplateFieldSearchQuery($search: String) {
        statusTemplates(search: $search) {
            edges {
                node {
                    id
                    name
                    color
                }
            }
        }
    }
`;

const StatusTemplateField: FunctionComponent<StatusTemplateFieldProps> = ({ name, setFieldValue, helpertext }) => {
  const classes = useStyles();
  const { t } = useFormatter();

  const [statusTemplateCreation, setStatusTemplateCreation] = useState<boolean>(false);
  const [statusTemplateInput, setStatusTemplateInput] = useState<string>('');
  const [statusTemplates, setStatusTemplates] = useState<{ label: string | undefined, value: string | undefined, color: string | undefined }[]>([]);

  const handleOpenStatusTemplateCreation = () => setStatusTemplateCreation(true);

  const handleCloseStatusTemplateCreation = () => setStatusTemplateCreation(false);

  const searchStatusTemplates = (event: React.KeyboardEvent) => {
    const target = event.target as HTMLInputElement;
    if (target !== null && target.value) {
      setStatusTemplateInput(event && target.value !== '0' ? target.value : '');
      fetchQuery(StatusTemplateFieldQuery, {
        search: event && target.value !== '0' ? target.value : '',
      })
        .toPromise()
        .then((data) => {
          const NewStatusTemplates = ((data as StatusTemplateFieldSearchQuery$data)?.statusTemplates?.edges ?? []).map((n) => ({
            label: n?.node.name,
            value: n?.node.id,
            color: n?.node.color,
          }));
          setStatusTemplates([...statusTemplates, ...NewStatusTemplates]);
        });
    }
  };

  return (
    <div style={{ marginTop: 20, width: '100%' }}>
      <Field
        component={AutocompleteField}
        name={name}
        multiple={false}
        textfieldprops={{
          variant: 'standard',
          label: t('Name'),
          helperText: helpertext,
          onFocus: searchStatusTemplates,
        }}
        noOptionsText={t('No available options')}
        options={statusTemplates}
        onInputChange={searchStatusTemplates}
        openCreate={handleOpenStatusTemplateCreation}
        renderOption={({ props, option }: { props: React.HTMLAttributes<HTMLLIElement>, option: { color: string, label: string } }) => (
          <li {...props}>
            <div className={classes.icon} style={{ color: option.color }}>
              <Label />
            </div>
            <div className={classes.text}>{option.label}</div>
          </li>
        )}
        classes={{ clearIndicator: classes.autoCompleteIndicator }}
      />
      <StatusTemplateCreation
        contextual={true}
        inputValueContextual={statusTemplateInput}
        openContextual={statusTemplateCreation}
        handleCloseContextual={handleCloseStatusTemplateCreation}
        creationCallback={(data: StatusTemplateCreationContextualMutation$data) => {
          setFieldValue(
            name,
            append(
              {
                name: data.statusTemplateAdd.name,
                id: data.statusTemplateAdd.id,
              },
            ),
          );
        }}
      />
    </div>
  );
};

export default StatusTemplateField;
