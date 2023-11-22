import React from 'react';
import { graphql } from 'react-relay';
import { Field, Form, Formik } from 'formik';
import Button from '@mui/material/Button';
import { TextField } from 'formik-mui';
import * as Yup from 'yup';
import makeStyles from '@mui/styles/makeStyles';
import { FormikConfig } from 'formik/dist/types';
import { useFormatter } from '../../../../components/i18n';
import formikFieldToEditInput from '../../../../utils/FormikUtils';
import type { Theme } from '../../../../components/Theme';
import { useVocabularyCategory_Vocabularynode$data } from '../../../../utils/hooks/__generated__/useVocabularyCategory_Vocabularynode.graphql';
import { fieldSpacingContainerStyle } from '../../../../utils/field';
import { MESSAGING$ } from '../../../../relay/environment';
import AutocompleteFreeSoloField from '../../../../components/AutocompleteFreeSoloField';
import { Option } from '../../common/form/ReferenceField';
import { RelayError } from '../../../../relay/relayTypes';
import useApiMutation from '../../../../utils/hooks/useApiMutation';
import { useSchemaEditionValidation, useMandatorySchemaAttributes } from '../../../../utils/hooks/useSchemaAttributes';

// Deprecated - https://mui.com/system/styles/basics/
// Do not use it for new code.
const useStyles = makeStyles<Theme>((theme) => ({
  buttons: {
    marginTop: 20,
    textAlign: 'right',
  },
  button: {
    marginLeft: theme.spacing(2),
  },
}));

const vocabularyMutationUpdate = graphql`
  mutation VocabularyEditionUpdateMutation($id: ID!, $input: [EditInput!]!) {
    vocabularyFieldPatch(id: $id, input: $input) {
      ...useVocabularyCategory_Vocabularynode
    }
  }
`;

const VOCABULARY_TYPE = 'Vocabulary';

interface VocabularyEditionFormikValues {
  name: string;
  description: string;
  aliases: { id: string; label: string; value: string }[];
  order: number | null | undefined;
}

const VocabularyEdition = ({
  handleClose,
  vocab,
}: {
  handleClose: () => void;
  vocab: useVocabularyCategory_Vocabularynode$data;
}) => {
  const { t_i18n } = useFormatter();
  const classes = useStyles();
  const basicShape = {
    name: Yup.string(),
    description: Yup.string(),
    order: Yup.number().nullable().integer(t_i18n('The value must be a number')),
  };
  const vocabularyValidator = useSchemaEditionValidation(
    VOCABULARY_TYPE,
    basicShape,
  );

  const mandatoryAttributes = useMandatorySchemaAttributes(VOCABULARY_TYPE);

  const [commitUpdateMutation] = useApiMutation(vocabularyMutationUpdate);

  const onSubmit: FormikConfig<VocabularyEditionFormikValues>['onSubmit'] = (
    values,
    { setSubmitting },
  ) => {
    const input = formikFieldToEditInput(
      {
        ...values,
        aliases: values.aliases.map((a) => a.value),
      },
      {
        name: vocab.name,
        aliases: vocab.aliases ?? [],
        description: vocab.description ?? '',
      },
    );
    if (input.length > 0) {
      commitUpdateMutation({
        variables: { id: vocab.id, input },
        onError: (error) => {
          const { errors } = (error as unknown as RelayError).res;
          MESSAGING$.notifyError(errors.at(0)?.data.reason);
          setSubmitting(false);
        },
        onCompleted: () => {
          setSubmitting(false);
          handleClose();
        },
      });
    } else {
      setSubmitting(false);
      handleClose();
    }
  };

  return (
    <Formik
      enableReinitialize={true}
      initialValues={{
        name: vocab.name,
        aliases: (vocab.aliases ?? []).map((n) => ({
          id: n,
          value: n,
          label: n,
        })) as { id: string; label: string; value: string }[],
        description: vocab.description ?? '',
        order: vocab.order,
      }}
      validationSchema={vocabularyValidator}
      onSubmit={onSubmit}
    >
      {({ submitForm, isSubmitting, isValid }) => (
        <Form style={{ margin: '20px 0 20px 0' }}>
          <Field
            component={TextField}
            variant="standard"
            name="name"
            label={t_i18n('Name')}
            required={(mandatoryAttributes.includes('name'))}
            fullWidth={true}
            disabled={vocab.builtIn}
          />
          <Field
            component={TextField}
            variant="standard"
            name="description"
            label={t_i18n('Description')}
            required={(mandatoryAttributes.includes('description'))}
            fullWidth={true}
            style={fieldSpacingContainerStyle}
          />
          <Field
            component={AutocompleteFreeSoloField}
            style={{ marginTop: 20 }}
            name="aliases"
            multiple={true}
            createLabel={t_i18n('Add')}
            textfieldprops={{ variant: 'standard', label: t_i18n('Aliases') }}
            options={(vocab.aliases ?? []).map((n) => ({
              id: n,
              value: n,
              label: n,
            }))}
            renderOption={(
              props: Record<string, unknown>,
              option: Option,
            ) => (
              <li {...props}>
                <div className={classes.text}>{option.label}</div>
              </li>
            )}
            classes={{ clearIndicator: classes.autoCompleteIndicator }}
          />
          <Field
            component={TextField}
            variant="standard"
            name="order"
            label={t_i18n('Order')}
            required={(mandatoryAttributes.includes('order'))}
            fullWidth={true}
            type="number"
            style={{ marginTop: 20 }}
          />
          <div className={classes.buttons}>
            <Button
              variant="contained"
              color="primary"
              onClick={submitForm}
              disabled={isSubmitting || !isValid}
              classes={{ root: classes.button }}
            >
              {t_i18n('Update')}
            </Button>
          </div>
        </Form>
      )}
    </Formik>
  );
};

export default VocabularyEdition;
