import React, { FunctionComponent } from 'react';
import makeStyles from '@mui/styles/makeStyles';
import { Field, Form, Formik, FormikConfig } from 'formik';
import Button from '@common/button/Button';
import { graphql } from 'react-relay';
import * as Yup from 'yup';
import Drawer, { DrawerControlledDialProps } from '@components/common/drawer/Drawer';
import { VocabulariesLinesPaginationQuery$variables } from '@components/settings/__generated__/VocabulariesLinesPaginationQuery.graphql';
import TextField from '../../../../components/TextField';
import type { Theme } from '../../../../components/Theme';
import { useFormatter } from '../../../../components/i18n';
import { VocabularyAddInput, VocabularyCategory, VocabularyCreationMutation } from './__generated__/VocabularyCreationMutation.graphql';
import { insertNode } from '../../../../utils/store';
import { FieldOption, fieldSpacingContainerStyle } from '../../../../utils/field';
import AutocompleteFreeSoloField from '../../../../components/AutocompleteFreeSoloField';
import useApiMutation from '../../../../utils/hooks/useApiMutation';
import CreateEntityControlledDial from '../../../../components/CreateEntityControlledDial';

interface VocabularyCreationProps {
  paginationOptions: VocabulariesLinesPaginationQuery$variables;
  category: VocabularyCategory;
}

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
  text: {
    display: 'inline-block',
    flexGrow: 1,
    marginLeft: 10,
  },
}));

const vocabularyAdd = graphql`
  mutation VocabularyCreationMutation($input: VocabularyAddInput!) {
    vocabularyAdd(input: $input) {
      ...useVocabularyCategory_Vocabularynode
    }
  }
`;

const labelValidation = (t: (v: string) => string) => Yup.object().shape({
  name: Yup.string().required(t('This field is required')),
  order: Yup.number().nullable(),
});

const VocabularyCreation: FunctionComponent<VocabularyCreationProps> = ({
  paginationOptions,
  category,
}) => {
  const classes = useStyles();
  const { t_i18n } = useFormatter();

  const [addVocab] = useApiMutation<VocabularyCreationMutation>(vocabularyAdd);

  interface FormInterface {
    name: string;
    description: string;
    aliases: { value: string }[];
    order: number;
  }

  const onSubmit: FormikConfig<FormInterface>['onSubmit'] = (
    values,
    { resetForm },
  ) => {
    const data: VocabularyAddInput = {
      name: values.name,
      description: values.description,
      aliases: values.aliases.map((a) => a.value),
      order: parseInt(String(values.order), 10),
      category,
    };
    addVocab({
      variables: {
        input: data,
      },
      updater: (store) => insertNode(
        store,
        'Pagination_vocabularies',
        paginationOptions,
        'vocabularyAdd',
      ),
      onCompleted: () => {
        resetForm();
      },
    });
  };

  const CreateVocabularyControlledDial = (props: DrawerControlledDialProps) => (
    <CreateEntityControlledDial entityType="Vocabulary" {...props} />
  );

  return (
    <Drawer
      title={t_i18n('Create a vocabulary')}
      controlledDial={CreateVocabularyControlledDial}
    >
      {({ onClose }) => (
        <Formik<FormInterface>
          initialValues={{
            name: '',
            description: '',
            aliases: [] as { value: string }[],
            order: 0,
          }}
          validationSchema={labelValidation(t_i18n)}
          onSubmit={(values, formikHelpers) => {
            onSubmit(values, formikHelpers);
            onClose();
          }}
          onReset={onClose}
        >
          {({ submitForm, handleReset, isSubmitting, isValid, dirty }) => (
            <Form>
              <Field
                component={TextField}
                variant="standard"
                name="name"
                label={t_i18n('Name')}
                fullWidth={true}
              />
              <Field
                component={TextField}
                variant="standard"
                name="description"
                label={t_i18n('Description')}
                fullWidth={true}
                style={fieldSpacingContainerStyle}
              />
              <Field
                component={AutocompleteFreeSoloField}
                style={fieldSpacingContainerStyle}
                name="aliases"
                multiple={true}
                textfieldprops={{
                  variant: 'standard',
                  label: t_i18n('Aliases'),
                }}
                options={[]}
                renderOption={(
                  props: Record<string, unknown>,
                  option: FieldOption,
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
                fullWidth={true}
                type="number"
                style={{ marginTop: 20 }}
              />
              <div className={classes.buttons}>
                <Button
                  variant="secondary"
                  onClick={handleReset}
                  disabled={isSubmitting}
                  classes={{ root: classes.button }}
                >
                  {t_i18n('Cancel')}
                </Button>
                <Button
                  onClick={submitForm}
                  disabled={isSubmitting || !isValid || !dirty}
                  classes={{ root: classes.button }}
                >
                  {t_i18n('Create')}
                </Button>
              </div>
            </Form>
          )}
        </Formik>
      )}
    </Drawer>
  );
};

export default VocabularyCreation;
