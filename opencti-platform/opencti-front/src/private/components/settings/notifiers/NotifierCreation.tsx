import React, {
  createRef,
  FunctionComponent,
  MutableRefObject,
  useRef,
  useState,
} from 'react';
import { Field, Form, Formik } from 'formik';
import validator from '@rjsf/validator-ajv8';
import CoreForm from '@rjsf/core';
import * as Yup from 'yup';
import JsonForm from '@rjsf/mui';
import Drawer from '@mui/material/Drawer';
import Typography from '@mui/material/Typography';
import Button from '@mui/material/Button';
import IconButton from '@mui/material/IconButton';
import makeStyles from '@mui/styles/makeStyles';
import Fab from '@mui/material/Fab';
import { Add, Close } from '@mui/icons-material';
import { graphql, useMutation, useQueryLoader } from 'react-relay';
import { RecordSourceSelectorProxy } from 'relay-runtime';
import { FormikHelpers } from 'formik/dist/types';
import { useFormatter } from '../../../../components/i18n';
import { Theme } from '../../../../components/Theme';
import TextField from '../../../../components/TextField';
import { handleErrorInForm } from '../../../../relay/environment';
import { fieldSpacingContainerStyle } from '../../../../utils/field';
import { insertNode } from '../../../../utils/store';
import ObjectMembersField from '../../common/form/ObjectMembersField';
import { Option } from '../../common/form/ReferenceField';
import { NotifiersLinesPaginationQuery$variables } from './__generated__/NotifiersLinesPaginationQuery.graphql';
import NotifierConnectorField from '../../common/form/NotifierConnectorField';
import { uiSchema } from './NotifierUtils';
import NotifierTestDialog, { notifierTestQuery } from './NotifierTestDialog';
import { NotifierTestDialogQuery } from './__generated__/NotifierTestDialogQuery.graphql';

const useStyles = makeStyles<Theme>((theme) => ({
  drawerPaper: {
    minHeight: '100vh',
    width: '50%',
    position: 'fixed',
    transition: theme.transitions.create('width', {
      easing: theme.transitions.easing.sharp,
      duration: theme.transitions.duration.enteringScreen,
    }),
    padding: 0,
  },
  createButton: {
    position: 'fixed',
    bottom: 30,
    right: 230,
  },
  buttons: {
    marginTop: 20,
    textAlign: 'right',
  },
  button: {
    marginLeft: theme.spacing(2),
  },
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
}));

const notifierMutation = graphql`
  mutation NotifierCreationMutation($input: NotifierAddInput!) {
    notifierAdd(input: $input) {
      id
      name
      description
      entity_type
      parent_types
      notifier_connector {
        name
      }
      ...NotifierLine_node
    }
  }
`;

interface NotifierAddInput {
  name: string;
  description: string;
  notifier_connector_id?: Option;
  authorized_members: Option[];
}

interface NotifierFormProps {
  updater: (store: RecordSourceSelectorProxy, key: string) => void;
  onReset?: () => void;
  onCompleted?: () => void;
  inputValue?: string;
}

const notifierValidation = (t: (value: string) => string) => Yup.object().shape({
  name: Yup.string().required(t('This field is required')),
  description: Yup.string().nullable(),
  notifier_connector_id: Yup.object().required(t('This field is required')),
  authorized_members: Yup.array().nullable(),
});

type NotifierFormikHelpers = Pick<
FormikHelpers<NotifierAddInput>,
'setErrors' | 'setSubmitting' | 'resetForm'
>;

export const NotifierCreationForm: FunctionComponent<NotifierFormProps> = ({
  updater,
  onReset,
  inputValue,
  onCompleted,
}) => {
  const classes = useStyles();
  const { t } = useFormatter();
  const formRef = createRef<CoreForm>();
  const [open, setOpen] = useState(false);
  const [connector, setCurrentConnector] = useState<
  Option & { schema?: string; ui_schema?: string }
  >();
  const initialValues: NotifierAddInput = {
    name: inputValue || '',
    description: '',
    authorized_members: [],
  };
  const [commit] = useMutation(notifierMutation);
  const submitForm = (
    values: NotifierAddInput,
    current: MutableRefObject<CoreForm>['current'] | null,
    { setErrors, setSubmitting, resetForm }: NotifierFormikHelpers,
  ) => {
    notifierValidation(t)
      .validate(values)
      .then(() => {
        if (current && current.validateForm()) {
          const input = {
            name: values.name,
            description: values.description,
            notifier_connector_id: values.notifier_connector_id?.value,
            notifier_configuration: JSON.stringify(current.state.formData),
            authorized_members: values.authorized_members.map(({ value }) => ({
              id: value,
              access_right: 'view',
            })),
          };
          commit({
            variables: { input },
            updater: (store) => {
              if (updater) {
                updater(store, 'notifierAdd');
              }
            },
            onError: (error: Error) => {
              handleErrorInForm(error, setErrors);
              setSubmitting(false);
            },
            onCompleted: () => {
              setSubmitting(false);
              resetForm();
              if (onCompleted) {
                onCompleted();
              }
            },
          });
        }
      });
  };

  const notifierConfiguration = useRef<string>(' {}');
  const [testQueryRef, sendTest] = useQueryLoader<NotifierTestDialogQuery>(notifierTestQuery);
  return (
    <Formik<NotifierAddInput>
      initialValues={initialValues}
      validationSchema={notifierValidation(t)}
      onSubmit={() => {}}
      onReset={onReset}
    >
      {({
        setErrors,
        resetForm,
        handleReset,
        values,
        setSubmitting,
        isSubmitting,
        setFieldValue,
      }) => (
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
            name="description"
            variant="standard"
            label={t('Description')}
            fullWidth={true}
            style={{ marginTop: 20 }}
          />
          <NotifierConnectorField
            name="notifier_connector_id"
            onChange={(name, data) => setCurrentConnector(data)}
            style={{ marginTop: 20 }}
          />
          <ObjectMembersField
            label={'Accessible for'}
            style={fieldSpacingContainerStyle}
            onChange={setFieldValue}
            multiple={true}
            name="authorized_members"
          />
          {connector && (
            <JsonForm
              uiSchema={{
                ...JSON.parse(connector.ui_schema ?? ' {}'),
                ...uiSchema,
              }}
              ref={formRef}
              showErrorList={false}
              liveValidate
              schema={JSON.parse(connector.schema ?? ' {}')}
              formData={JSON.parse(notifierConfiguration.current)}
              validator={validator}
              onChange={(newValue) => {
                notifierConfiguration.current = JSON.stringify(
                  newValue.formData,
                );
              }}
            />
          )}
          <div className={classes.buttons}>
            <Button
              variant="contained"
              color="primary"
              onClick={() => {
                notifierConfiguration.current = JSON.stringify(
                  formRef.current?.state.formData,
                );
                setOpen(true);
              }}
              disabled={isSubmitting}
              classes={{ root: classes.button }}
            >
              {t('Test')}
            </Button>
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
              onClick={() => submitForm(values, formRef.current, {
                setErrors,
                setSubmitting,
                resetForm,
              })
              }
              classes={{ root: classes.button }}
            >
              {t('Create')}
            </Button>
          </div>
          <NotifierTestDialog
            open={open}
            onClose={() => setOpen(false)}
            queryRef={testQueryRef}
            onTest={(notifier_test_id) => {
              if (values.notifier_connector_id) {
                sendTest(
                  {
                    input: {
                      notifier_test_id,
                      notifier_connector_id: values.notifier_connector_id.value,
                      notifier_configuration: notifierConfiguration.current,
                    },
                  },
                  { fetchPolicy: 'network-only' },
                );
              }
            }}
          />
        </Form>
      )}
    </Formik>
  );
};

const NotifierCreation: FunctionComponent<{
  contextual?: boolean;
  display?: boolean;
  inputValue?: string;
  paginationOptions: NotifiersLinesPaginationQuery$variables;
}> = ({ inputValue, paginationOptions }) => {
  const { t } = useFormatter();
  const classes = useStyles();
  const [open, setOpen] = useState(false);
  const handleOpen = () => setOpen(true);
  const handleClose = () => setOpen(false);
  const updater = (store: RecordSourceSelectorProxy) => insertNode(store, 'Pagination_notifiers', paginationOptions, 'notifierAdd');
  return (
    <>
      <Fab
        onClick={handleOpen}
        color="secondary"
        aria-label="Add"
        className={classes.createButton}
      >
        <Add />
      </Fab>
      <Drawer
        open={open}
        anchor="right"
        elevation={1}
        sx={{ zIndex: 1202 }}
        classes={{ paper: classes.drawerPaper }}
        onClose={handleClose}
      >
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
          <Typography variant="h6">{t('Create a notifier')}</Typography>
        </div>
        <div className={classes.container}>
          <NotifierCreationForm
            inputValue={inputValue}
            updater={updater}
            onCompleted={handleClose}
            onReset={handleClose}
          />
        </div>
      </Drawer>
    </>
  );
};

export default NotifierCreation;
