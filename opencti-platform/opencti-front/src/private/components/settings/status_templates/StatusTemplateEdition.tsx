import React, { FunctionComponent } from 'react';
import { graphql, useFragment } from 'react-relay';
import { Form, Formik, Field } from 'formik';
import { pick } from 'ramda';
import Typography from '@mui/material/Typography';
import IconButton from '@mui/material/IconButton';
import { Close } from '@mui/icons-material';
import * as Yup from 'yup';
import makeStyles from '@mui/styles/makeStyles';
import { useFormatter } from '../../../../components/i18n';
import { commitMutation } from '../../../../relay/environment';
import TextField from '../../../../components/TextField';
import ColorPickerField from '../../../../components/ColorPickerField';
import { Theme } from '../../../../components/Theme';
import { StatusTemplateEdition_statusTemplate$key } from './__generated__/StatusTemplateEdition_statusTemplate.graphql';

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
  title: {
    float: 'left',
  },
}));

export const StatusTemplateEditionFragment = graphql`
  fragment StatusTemplateEdition_statusTemplate on StatusTemplate {
    id
    name
    color
  }
`;

const statusTemplateMutationFieldPatch = graphql`
  mutation StatusTemplateEditionFieldPatchMutation(
    $id: ID!
    $input: [EditInput!]!
  ) {
    statusTemplateFieldPatch(id: $id, input: $input) {
      id
      name
      color
    }
  }
`;

const statusTemplateEditionFocus = graphql`
  mutation StatusTemplateEditionFocusMutation($id: ID!, $input: EditContext!) {
    statusTemplateContextPatch(id: $id, input: $input) {
      id
    }
  }
`;

const statusTemplateValidation = (t: (name: string | object) => string) => Yup.object().shape({
  name: Yup.string().required(t('This field is required')),
  color: Yup.string().required(t('This field is required')),
});

interface StatusTemplateEditionProps {
  handleClose: () => void;
  statusTemplate: StatusTemplateEdition_statusTemplate$key;
}

const StatusTemplateEdition: FunctionComponent<StatusTemplateEditionProps> = ({
  handleClose,
  statusTemplate,
}) => {
  const classes = useStyles();
  const data = useFragment(StatusTemplateEditionFragment, statusTemplate);

  const { t } = useFormatter();
  const initialValues = pick(['name', 'color'], data);

  const handleChangeFocus = (name: string) => {
    commitMutation({
      mutation: statusTemplateEditionFocus,
      variables: {
        id: data.id,
        input: {
          focusOn: name,
        },
      },
      updater: undefined,
      optimisticUpdater: undefined,
      optimisticResponse: undefined,
      onCompleted: undefined,
      onError: undefined,
      setSubmitting: undefined,
    });
  };

  const handleSubmitField = (name: string, value: string) => {
    statusTemplateValidation(t)
      .validateAt(name, { [name]: value })
      .then(() => {
        commitMutation({
          mutation: statusTemplateMutationFieldPatch,
          variables: {
            id: data.id,
            input: { key: name, value: value || '' },
          },
          updater: undefined,
          optimisticUpdater: undefined,
          optimisticResponse: undefined,
          onCompleted: undefined,
          onError: undefined,
          setSubmitting: undefined,
        });
      })
      .catch(() => false);
  };

  return (
    <>
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
          {t('Update a status template')}
        </Typography>
        <div className="clearfix" />
      </div>
      <div className={classes.container}>
        <Formik
          enableReinitialize={true}
          initialValues={initialValues}
          validationSchema={statusTemplateValidation(t)}
          onSubmit={() => {}}
        >
          {() => (
            <Form style={{ margin: '20px 0 20px 0' }}>
              <Field
                component={TextField}
                variant="standard"
                name="name"
                label={t('Name')}
                fullWidth={true}
                onFocus={handleChangeFocus}
                onSubmit={handleSubmitField}
              />
              <Field
                component={ColorPickerField}
                name="color"
                label={t('Color')}
                fullWidth={true}
                style={{ marginTop: 20 }}
                onFocus={handleChangeFocus}
                onSubmit={handleSubmitField}
              />
            </Form>
          )}
        </Formik>
      </div>
    </>
  );
};

export default StatusTemplateEdition;
