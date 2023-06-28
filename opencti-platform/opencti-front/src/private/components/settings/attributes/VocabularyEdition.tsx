import React from 'react';
import { graphql, useMutation } from 'react-relay';
import { Field, Form, Formik } from 'formik';
import Typography from '@mui/material/Typography';
import Button from '@mui/material/Button';
import IconButton from '@mui/material/IconButton';
import { Close } from '@mui/icons-material';
import { TextField } from 'formik-mui';
import * as Yup from 'yup';
import makeStyles from '@mui/styles/makeStyles';
import { FormikConfig } from 'formik/dist/types';
import { useFormatter } from '../../../../components/i18n';
import formikFieldToEditInput from '../../../../utils/FormikUtils';
import { Theme } from '../../../../components/Theme';
import { useVocabularyCategory_Vocabularynode$data } from '../../../../utils/hooks/__generated__/useVocabularyCategory_Vocabularynode.graphql';
import { fieldSpacingContainerStyle } from '../../../../utils/field';
import { MESSAGING$ } from '../../../../relay/environment';
import AutocompleteFreeSoloField from '../../../../components/AutocompleteFreeSoloField';
import { Option } from '../../common/form/ReferenceField';
import { RelayError } from '../../../../relay/relayTypes';

const useStyles = makeStyles<Theme>((theme) => ({
  header: {
    backgroundColor: theme.palette.background.nav,
    padding: '20px 20px 20px 60px',
  },
  closeButton: {
    position: 'absolute',
    top: 12,
    left: 5,
    color: 'inherit',
  },
  container: {
    padding: '10px 20px 20px 20px',
  },
  appBar: {
    width: '100%',
    zIndex: theme.zIndex.drawer + 1,
    borderBottom: '1px solid #5c5c5c',
  },
  title: {
    float: 'left',
  },
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

const attributeValidation = (t: (s: string) => string) => Yup.object().shape({
  name: Yup.string().required(t('This field is required')),
  description: Yup.string().nullable(),
  order: Yup.number().nullable(),
});

interface VocabularyEditionFormikValues {
  name: string;
  description: string;
  aliases: { id: string; label: string; value: string }[];
  order: number | null;
}

const VocabularyEdition = ({
  handleClose,
  vocab,
}: {
  handleClose: () => void;
  vocab: useVocabularyCategory_Vocabularynode$data;
}) => {
  const { t } = useFormatter();
  const classes = useStyles();

  const [commitUpdateMutation] = useMutation(vocabularyMutationUpdate);

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
    <div>
      <div className={classes.header}>
        <IconButton
          aria-label="Close"
          className={classes.closeButton}
          onClick={handleClose}
          size="large"
          color="primary"
        >
          <Close fontSize="small" color="primary" />
        </IconButton>
        <Typography variant="h6" classes={{ root: classes.title }}>
          {t('Update an attribute')}
        </Typography>
        <div className="clearfix" />
      </div>
      <div className={classes.container}>
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
          validationSchema={attributeValidation(t)}
          onSubmit={onSubmit}
        >
          {({ submitForm, isSubmitting }) => (
            <Form style={{ margin: '20px 0 20px 0' }}>
              <Field
                component={TextField}
                variant="standard"
                name="name"
                label={t('Name')}
                fullWidth={true}
                disabled={vocab.builtIn}
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
                style={{ marginTop: 20 }}
                name="aliases"
                multiple={true}
                createLabel={t('Add')}
                textfieldprops={{ variant: 'standard', label: t('Aliases') }}
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
                label={t('Order')}
                fullWidth={true}
                type="number"
                style={{ marginTop: 20 }}
              />
              <div className={classes.buttons}>
                <Button
                  variant="contained"
                  color="primary"
                  onClick={submitForm}
                  disabled={isSubmitting}
                  classes={{ root: classes.button }}
                >
                  {t('Update')}
                </Button>
              </div>
            </Form>
          )}
        </Formik>
      </div>
    </div>
  );
};

export default VocabularyEdition;
