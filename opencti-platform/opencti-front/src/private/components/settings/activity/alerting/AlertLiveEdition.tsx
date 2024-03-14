import { Close } from '@mui/icons-material';
import IconButton from '@mui/material/IconButton';
import Typography from '@mui/material/Typography';
import makeStyles from '@mui/styles/makeStyles';
import { Field, Form, Formik } from 'formik';
import { FormikConfig } from 'formik/dist/types';
import React, { FunctionComponent, useEffect } from 'react';
import { graphql, PreloadedQuery, useFragment, useMutation, usePreloadedQuery } from 'react-relay';
import Box from '@mui/material/Box';
import FilterIconButton from '../../../../../components/FilterIconButton';
import { useFormatter } from '../../../../../components/i18n';
import MarkdownField from '../../../../../components/MarkdownField';
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
import { liveActivityTriggerValidation } from './AlertLiveCreation';
import useFiltersState from '../../../../../utils/filters/useFiltersState';

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

const AlertLiveEdition: FunctionComponent<AlertLiveEditionProps> = ({
  queryRef,
  handleClose,
}) => {
  const { t_i18n } = useFormatter();
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
  const [commitFieldPatch] = useMutation(alertLiveEditionFieldPatch);
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
    return liveActivityTriggerValidation(t_i18n)
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
  const handleSubmitFieldOptions = (name: string, value: { value: string }[]) => liveActivityTriggerValidation(t_i18n)
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
                fullWidth={true}
                onSubmit={handleSubmitField}
              />
              <Field
                component={MarkdownField}
                name="description"
                label={t_i18n('Description')}
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
              />
              <ObjectMembersField
                label={'Recipients'}
                style={fieldSpacingContainerStyle}
                onChange={handleSubmitFieldOptions}
                multiple={true}
                name={'recipients'}
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
