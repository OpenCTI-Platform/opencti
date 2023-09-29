import React, { FunctionComponent } from 'react';
import makeStyles from '@mui/styles/makeStyles';
import { Field, Form, Formik, FormikConfig } from 'formik';
import Button from '@mui/material/Button';
import { graphql, useMutation } from 'react-relay';
import * as Yup from 'yup';
import Drawer, { DrawerVariant } from '@components/common/drawer/Drawer';
import TextField from '../../../../components/TextField';
import type { Theme } from '../../../../components/Theme';
import { useFormatter } from '../../../../components/i18n';
import { VocabularyAddInput, VocabularyCategory, VocabularyCreationMutation } from './__generated__/VocabularyCreationMutation.graphql';
import { insertNode } from '../../../../utils/store';
import { VocabulariesLines_DataQuery$variables } from './__generated__/VocabulariesLines_DataQuery.graphql';
import { fieldSpacingContainerStyle } from '../../../../utils/field';
import { Option } from '../../common/form/ReferenceField';
import AutocompleteFreeSoloField from '../../../../components/AutocompleteFreeSoloField';

interface VocabularyCreationProps {
  paginationOptions: VocabulariesLines_DataQuery$variables;
  category: VocabularyCategory;
}

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
  const { t } = useFormatter();

  const [addVocab] = useMutation<VocabularyCreationMutation>(vocabularyAdd);

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

  return (
    <Drawer
      title={t('Create a vocabulary')}
      variant={DrawerVariant.createWithPanel}
    >
      {({ onClose }) => (
        <Formik<FormInterface>
          initialValues={{
            name: '',
            description: '',
            aliases: [] as { value: string }[],
            order: 0,
          }}
          validationSchema={labelValidation(t)}
          onSubmit={(values, formikHelpers) => {
            onSubmit(values, formikHelpers);
            onClose();
          }}
          onReset={onClose}
        >
          {({ submitForm, handleReset, isSubmitting, isValid, dirty }) => (
            <Form style={{ margin: '20px 0 20px 0' }}>
              <Field
                component={TextField}
                variant="standard"
                name="name"
                label={t('Name')}
                fullWidth={true}
              />
              <Field
                component={TextField}
                variant="standard"
                name="description"
                label={t('Description')}
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
                  label: t('Aliases'),
                }}
                options={[]}
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
                label={t('Order')}
                fullWidth={true}
                type="number"
                style={{ marginTop: 20 }}
              />
              <div className={classes.buttons}>
                <Button
                  variant="contained"
                  onClick={handleReset}
                  disabled={isSubmitting}
                  classes={{ root: classes.button }}
                >
                  {t('Cancel')}
                </Button>
                <Button
                  variant="contained"
                  color="secondary"
                  onClick={submitForm}
                  disabled={isSubmitting || !isValid || !dirty}
                  classes={{ root: classes.button }}
                >
                  {t('Create')}
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
