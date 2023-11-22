import React, { FunctionComponent } from 'react';
import makeStyles from '@mui/styles/makeStyles';
import { Field, Form, Formik, FormikConfig } from 'formik';
import Button from '@mui/material/Button';
import { graphql } from 'react-relay';
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
import useApiMutation from '../../../../utils/hooks/useApiMutation';
import { useSchemaCreationValidation, useMandatorySchemaAttributes } from '../../../../utils/hooks/useSchemaAttributes';

interface VocabularyCreationProps {
  paginationOptions: VocabulariesLines_DataQuery$variables;
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

const OBJECT_TYPE = 'Vocabulary';

const VocabularyCreation: FunctionComponent<VocabularyCreationProps> = ({
  paginationOptions,
  category,
}) => {
  const classes = useStyles();
  const { t_i18n } = useFormatter();
  const basicShape = {
    name: Yup.string(),
    description: Yup.string(),
    order: Yup.number().nullable(),
  };
  const validator = useSchemaCreationValidation(
    OBJECT_TYPE,
    basicShape,
  );
  const mandatoryAttributes = useMandatorySchemaAttributes(OBJECT_TYPE);

  const [addVocab] = useApiMutation<VocabularyCreationMutation>(vocabularyAdd);

  interface FormInterface {
    name: string;
    description: string;
    aliases: { value: string }[];
    order: number;
    category: string;
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
      title={t_i18n('Create a vocabulary')}
      variant={DrawerVariant.createWithPanel}
    >
      {({ onClose }) => (
        <Formik<FormInterface>
          initialValues={{
            name: '',
            description: '',
            aliases: [] as { value: string }[],
            order: 0,
            category,
          }}
          validationSchema={validator}
          onSubmit={(values, formikHelpers) => {
            onSubmit(values, formikHelpers);
            onClose();
          }}
          onReset={onClose}
        >
          {({ submitForm, handleReset, isSubmitting }) => (
            <Form style={{ margin: '20px 0 20px 0' }}>
              <Field
                component={TextField}
                variant="standard"
                name="name"
                label={t_i18n('Name')}
                required={(mandatoryAttributes.includes('name'))}
                fullWidth={true}
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
                  onClick={handleReset}
                  disabled={isSubmitting}
                  classes={{ root: classes.button }}
                >
                  {t_i18n('Cancel')}
                </Button>
                <Button
                  variant="contained"
                  color="secondary"
                  onClick={submitForm}
                  disabled={isSubmitting}
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
