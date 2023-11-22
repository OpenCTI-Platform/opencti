import { Close } from '@mui/icons-material';
import IconButton from '@mui/material/IconButton';
import Typography from '@mui/material/Typography';
import makeStyles from '@mui/styles/makeStyles';
import { Field, Form, Formik } from 'formik';
import { FormikConfig } from 'formik/dist/types';
import React, { FunctionComponent, useEffect } from 'react';
import * as Yup from 'yup';
import { graphql, PreloadedQuery, useFragment, usePreloadedQuery } from 'react-relay';
import Box from '@mui/material/Box';
import FilterIconButton from '../../../../../components/FilterIconButton';
import { useFormatter } from '../../../../../components/i18n';
import MarkdownField from '../../../../../components/fields/MarkdownField';
import TextField from '../../../../../components/TextField';
import type { Theme } from '../../../../../components/Theme';
import { convertNotifiers } from '../../../../../utils/edition';
import { fieldSpacingContainerStyle } from '../../../../../utils/field';
import { deserializeFilterGroupForFrontend, serializeFilterGroupForBackend } from '../../../../../utils/filters/filtersUtils';
import ObjectMembersField from '../../../common/form/ObjectMembersField';
import NotifierField from '../../../common/form/NotifierField';
import { Option } from '../../../common/form/ReferenceField';
import Filters from '../../../common/lists/Filters';
import { AlertEditionQuery } from './__generated__/AlertEditionQuery.graphql';
import { AlertingPaginationQuery$variables } from './__generated__/AlertingPaginationQuery.graphql';
import { AlertLiveEdition_trigger$key } from './__generated__/AlertLiveEdition_trigger.graphql';
import { alertEditionQuery } from './AlertEditionQuery';
import useFiltersState from '../../../../../utils/filters/useFiltersState';
import useApiMutation from '../../../../../utils/hooks/useApiMutation';
import { useSchemaEditionValidation, useMandatorySchemaAttributes } from '../../../../../utils/hooks/useSchemaAttributes';

interface AlertLiveEditionProps {
  handleClose: () => void;
  queryRef: PreloadedQuery<AlertEditionQuery>;
  paginationOptions?: AlertingPaginationQuery$variables;
}

interface AlertLiveFormValues {
  name?: string;
  notifiers: { value: string; label: string }[];
  recipients: { value: string; label: string }[];
}

const alertLiveEditionFragment = graphql`
  fragment AlertLiveEdition_trigger on Trigger {
    id
    name
    trigger_type
    event_types
    description
    filters
    created
    modified
    notifiers {
      id
      name
    }
    recipients {
      id
      name
    }
  }
`;

const alertLiveEditionFieldPatch = graphql`
  mutation AlertLiveEditionFieldPatchMutation($id: ID!, $input: [EditInput!]!) {
    triggerActivityFieldPatch(id: $id, input: $input) {
      ...AlertLiveEdition_trigger
    }
  }
`;

// Deprecated - https://mui.com/system/styles/basics/
// Do not use it for new code.
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

const OBJECT_TYPE = 'Trigger';

const AlertLiveEdition: FunctionComponent<AlertLiveEditionProps> = ({
  queryRef,
  handleClose,
}) => {
  const { t_i18n } = useFormatter();

  const basicShape: Yup.ObjectShape = {
    name: Yup.string(),
    description: Yup.string().nullable(),
    notifiers: Yup.array().nullable(),
    recipients: Yup.array().min(1, t_i18n('Minimum one recipient')),
  };
  const mandatoryAttributes = useMandatorySchemaAttributes(OBJECT_TYPE);
  const validator = useSchemaEditionValidation(
    OBJECT_TYPE,
    basicShape,
  );

  const classes = useStyles();
  const data = usePreloadedQuery<AlertEditionQuery>(
    alertEditionQuery,
    queryRef,
  );
  const trigger = useFragment<AlertLiveEdition_trigger$key>(
    alertLiveEditionFragment,
    data.triggerKnowledge,
  );
  const [filters, helpers] = useFiltersState(deserializeFilterGroupForFrontend(trigger?.filters ?? undefined) ?? undefined);
  const [commitFieldPatch] = useApiMutation(alertLiveEditionFieldPatch);
  useEffect(() => {
    commitFieldPatch({
      variables: {
        id: trigger?.id,
        input: {
          key: 'filters',
          value: serializeFilterGroupForBackend(filters),
        },
      },
    });
  }, [filters]);
  const onSubmit: FormikConfig<AlertLiveFormValues>['onSubmit'] = (
    values,
    { setSubmitting },
  ) => {
    commitFieldPatch({
      variables: {
        id: trigger?.id,
        input: values,
      },
      onCompleted: () => {
        setSubmitting(false);
        handleClose();
      },
    });
  };
  const handleSubmitField = (
    name: string,
    value: Option | string | string[],
  ) => {
    return validator
      .validateAt(name, { [name]: value })
      .then(() => {
        commitFieldPatch({
          variables: {
            id: trigger?.id,
            input: { key: name, value: value || '' },
          },
        });
      })
      .catch(() => false);
  };
  const handleSubmitFieldOptions = (name: string, value: { value: string }[]) => validator
    .validateAt(name, { [name]: value })
    .then(() => {
      commitFieldPatch({
        variables: {
          id: trigger?.id,
          input: { key: name, value: value?.map(({ value: v }) => v) ?? '' },
        },
      });
    })
    .catch(() => false);

  const initialValues = {
    name: trigger?.name,
    description: trigger?.description,
    notifiers: convertNotifiers(trigger),
    recipients: (trigger?.recipients ?? []).map((n) => ({
      label: n?.name,
      value: n?.id,
    })),
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
          {t_i18n('Update an activity live trigger')}
        </Typography>
        <div className="clearfix" />
      </div>
      <div className={classes.container}>
        <Formik
          enableReinitialize={true}
          initialValues={initialValues as never}
          onSubmit={onSubmit}
        >
          {() => (
            <Form style={{ margin: '20px 0 20px 0' }}>
              <Field
                component={TextField}
                variant="standard"
                name="name"
                label={t_i18n('Name')}
                required={(mandatoryAttributes.includes('name'))}
                fullWidth={true}
                onSubmit={handleSubmitField}
              />
              <Field
                component={MarkdownField}
                name="description"
                label={t_i18n('Description')}
                required={(mandatoryAttributes.includes('description'))}
                fullWidth={true}
                multiline={true}
                rows="4"
                onSubmit={handleSubmitField}
                style={{ marginTop: 20 }}
              />
              <NotifierField
                name="notifiers"
                onChange={(name, values) => handleSubmitField(
                  name,
                  values.map(({ value }) => value),
                )
                }
                required={(mandatoryAttributes.includes('notifiers'))}
              />
              <ObjectMembersField
                label={'Recipients'}
                style={fieldSpacingContainerStyle}
                onChange={handleSubmitFieldOptions}
                multiple={true}
                name={'recipients'}
                // required is true because of minimum one recipients
                required={(mandatoryAttributes.includes('recipients') || true)}
              />
              <Box
                sx={{
                  display: 'flex',
                  gap: 1,
                  marginTop: '20px',
                }}
              >
                <Filters
                  availableFilterKeys={[
                    'event_type',
                    'event_scope',
                    'members_user',
                    'members_group',
                    'members_organization',
                  ]}
                  helpers={helpers}
                  searchContext={{ entityTypes: ['History'] }}
                />
              </Box>
              <div className="clearfix" />
              {filters && (
                <FilterIconButton
                  filters={filters}
                  styleNumber={2}
                  helpers={helpers}
                  entityTypes={['History']}
                />
              )}
            </Form>
          )}
        </Formik>
      </div>
    </div>
  );
};

export default AlertLiveEdition;
