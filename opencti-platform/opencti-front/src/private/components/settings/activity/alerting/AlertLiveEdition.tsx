import { Close } from '@mui/icons-material';
import IconButton from '@mui/material/IconButton';
import Typography from '@mui/material/Typography';
import makeStyles from '@mui/styles/makeStyles';
import { Field, Form, Formik } from 'formik';
import { FormikConfig } from 'formik/dist/types';
import * as R from 'ramda';
import React, { FunctionComponent } from 'react';
import { graphql, PreloadedQuery, useFragment, useMutation, usePreloadedQuery } from 'react-relay';
import FilterIconButton from '../../../../../components/FilterIconButton';
import { useFormatter } from '../../../../../components/i18n';
import MarkdownField from '../../../../../components/MarkdownField';
import TextField from '../../../../../components/TextField';
import { Theme } from '../../../../../components/Theme';
import { convertNotifiers } from '../../../../../utils/edition';
import { fieldSpacingContainerStyle } from '../../../../../utils/field';
import { isUniqFilter } from '../../../../../utils/filters/filtersUtils';
import ObjectMembersField from '../../../common/form/ObjectMembersField';
import NotifierField from '../../../common/form/NotifierField';
import { Option } from '../../../common/form/ReferenceField';
import Filters from '../../../common/lists/Filters';
import { AlertEditionQuery } from './__generated__/AlertEditionQuery.graphql';
import { AlertingPaginationQuery$variables } from './__generated__/AlertingPaginationQuery.graphql';
import { AlertLiveEdition_trigger$key } from './__generated__/AlertLiveEdition_trigger.graphql';
import { alertEditionQuery } from './AlertEditionQuery';
import { liveActivityTriggerValidation } from './AlertLiveCreation';

interface AlertLiveEditionProps {
  handleClose: () => void
  queryRef: PreloadedQuery<AlertEditionQuery>
  paginationOptions?: AlertingPaginationQuery$variables
}

interface AlertLiveFormValues {
  name?: string
  notifiers: { value: string, label: string }[];
  recipients: { value: string, label: string }[];
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
  mutation AlertLiveEditionFieldPatchMutation(
    $id: ID!
    $input: [EditInput!]!
  ) {
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

const AlertLiveEdition: FunctionComponent<AlertLiveEditionProps> = ({ queryRef, handleClose }) => {
  const { t } = useFormatter();
  const classes = useStyles();
  const data = usePreloadedQuery<AlertEditionQuery>(alertEditionQuery, queryRef);
  const trigger = useFragment<AlertLiveEdition_trigger$key>(alertLiveEditionFragment, data.triggerKnowledge);
  const filters = JSON.parse(trigger?.filters ?? '{}');
  const [commitFieldPatch] = useMutation(alertLiveEditionFieldPatch);
  const onSubmit: FormikConfig<AlertLiveFormValues>['onSubmit'] = (values, { setSubmitting }) => {
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
  const handleSubmitField = (name: string, value: Option | string | string[]) => {
    return liveActivityTriggerValidation(t).validateAt(name, { [name]: value }).then(() => {
      commitFieldPatch({
        variables: {
          id: trigger?.id,
          input: { key: name, value: value || '' },
        },
      });
    }).catch(() => false);
  };
  const handleSubmitFieldOptions = (name: string, value: { value: string }[]) => liveActivityTriggerValidation(t)
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
  const handleAddFilter = (key: string, id: string, value: Record<string, unknown> | string) => {
    if (filters[key] && filters[key].length > 0) {
      const updatedFilters = R.assoc(
        key,
        isUniqFilter(key)
          ? [{ id, value }]
          : R.uniqBy(R.prop('id'), [{ id, value }, ...filters[key]]),
        filters,
      );
      commitFieldPatch({
        variables: {
          id: trigger?.id,
          input: { key: 'filters', value: JSON.stringify(updatedFilters) },
        },
      });
    } else {
      const updatedFilters = R.assoc(key, [{ id, value }], filters);
      commitFieldPatch({
        variables: {
          id: trigger?.id,
          input: { key: 'filters', value: JSON.stringify(updatedFilters) },
        },
      });
    }
  };
  const handleRemoveFilter = (key: string) => {
    const updatedFilters = R.dissoc(key, filters);
    commitFieldPatch({
      variables: {
        id: trigger?.id,
        input: { key: 'filters', value: JSON.stringify(updatedFilters) },
      },
    });
  };

  const initialValues = {
    name: trigger?.name,
    description: trigger?.description,
    notifiers: convertNotifiers(trigger),
    recipients: (trigger?.recipients ?? []).map((n) => ({ label: n?.name, value: n?.id })),
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
          {t('Update an activity live trigger')}
        </Typography>
        <div className="clearfix" />
      </div>
      <div className={classes.container}>
        <Formik enableReinitialize={true} initialValues={initialValues as never} onSubmit={onSubmit}>
          {() => (
            <Form style={{ margin: '20px 0 20px 0' }}>
              <Field
                component={TextField}
                variant="standard"
                name="name"
                label={t('Name')}
                fullWidth={true}
                onSubmit={handleSubmitField}
              />
              <Field
                component={MarkdownField}
                name="description"
                label={t('Description')}
                fullWidth={true}
                multiline={true}
                rows="4"
                onSubmit={handleSubmitField}
                style={{ marginTop: 20 }}
              />
              <NotifierField
                name="notifiers"
                onChange={(name, values) => handleSubmitField(name, values.map(({ value }) => value))}
              />
              <ObjectMembersField
                label={'Recipients'}
                style={fieldSpacingContainerStyle}
                onChange={handleSubmitFieldOptions}
                multiple={true} name={'recipients'}
              />
              <div style={{ marginTop: 35 }}>
                <Filters
                  variant="text"
                  availableFilterKeys={[
                    'event_type',
                    'event_scope',
                    'members_user',
                    'members_group',
                    'members_organization',
                  ]}
                  handleAddFilter={handleAddFilter}
                  handleRemoveFilter={undefined}
                  handleSwitchFilter={undefined}
                  noDirectFilters={true}
                  disabled={undefined}
                  size={undefined}
                  fontSize={undefined}
                  availableEntityTypes={undefined}
                  availableRelationshipTypes={undefined}
                  allEntityTypes={undefined}
                  type={undefined}
                  availableRelationFilterTypes={undefined}
                />
              </div>
              <div className="clearfix" />
              <FilterIconButton
                filters={filters}
                handleRemoveFilter={handleRemoveFilter}
                classNameNumber={2}
              />
            </Form>
          )}
        </Formik>
      </div>
    </div>

  );
};

export default AlertLiveEdition;
