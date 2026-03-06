import React, { FunctionComponent, useState } from 'react';
import Grid from '@mui/material/Grid';
import { DraftRootFragment$data } from '@components/drafts/__generated__/DraftRootFragment.graphql';
import Label from '@common/label/Label';
import { useFormatter } from '../../../components/i18n';
import Card from '@common/card/Card';
import Security from '../../../utils/Security';
import { KNOWLEDGE_KNUPDATE } from '../../../utils/hooks/useGranted';
import IconButton from '@common/button/IconButton';
import { Add } from '@mui/icons-material';
import ItemAssignees from '../../../components/ItemAssignees';
import ItemParticipants from '../../../components/ItemParticipants';
import ItemAuthor from '../../../components/ItemAuthor';
import Dialog from '@common/dialog/Dialog';
import ObjectAssigneeField from '@components/common/form/ObjectAssigneeField';
import { FieldOption, fieldSpacingContainerStyle } from '../../../utils/field';
import DialogActions from '@mui/material/DialogActions';
import Button from '@common/button/Button';
import { Formik } from 'formik';
import { commitMutation } from '../../../relay/environment';
import { graphql } from 'react-relay';
import { FormikConfig } from 'formik/dist/types';
import ObjectParticipantField from '@components/common/form/ObjectParticipantField';
import { useGetCurrentUserAccessRight } from '../../../utils/authorizedMembers';

const draftEditMutation = graphql`
  mutation DraftBasicInformationMutation(
    $id: ID!
    $input: [EditInput!]!
  ) {
    draftWorkspaceFieldPatch(id: $id, input: $input) {
      ...DraftRootFragment
    }
  }
`;

interface DraftBasicInformationProps {
  draft: DraftRootFragment$data;
}

interface DraftAddAssigneeInput {
  objectAssignee: FieldOption[];
}

interface DraftAddParticipantInput {
  objectParticipant: FieldOption[];
}

const DraftBasicInformation: FunctionComponent<DraftBasicInformationProps> = ({ draft }) => {
  const { t_i18n } = useFormatter();
  const [openAddAssignee, setOpenAddAssignee] = useState(false);
  const [openAddParticipant, setOpenAddParticipant] = useState(false);
  const currentAccessRight = useGetCurrentUserAccessRight(draft.currentUserAccessRight);

  const handleToggleAddAssignee = () => {
    setOpenAddAssignee(!openAddAssignee);
  };

  const handleToggleAddParticipant = () => {
    setOpenAddParticipant(!openAddParticipant);
  };

  const onSubmitAssignees: FormikConfig<DraftAddAssigneeInput>['onSubmit'] = (values, { setSubmitting, resetForm }) => {
    const currentAssigneesIds = (draft.objectAssignee || []).map((assignee) => assignee.id);
    const valuesIds = values.objectAssignee.map((assignee) => assignee.value);
    const allIds = Array.from(new Set(currentAssigneesIds.concat(valuesIds))); // 'new Set' to merge without duplicates
    commitMutation({
      mutation: draftEditMutation,
      variables: {
        id: draft.id,
        input: {
          key: 'objectAssignee',
          value: allIds,
        },
      },
      onCompleted: () => {
        setSubmitting(false);
        resetForm();
        handleToggleAddAssignee();
      },
      setSubmitting: undefined,
      onError: undefined,
      optimisticResponse: undefined,
      optimisticUpdater: undefined,
      updater: undefined,
    });
  };

  const onSubmitParticipant: FormikConfig<DraftAddParticipantInput>['onSubmit'] = (values, { setSubmitting, resetForm }) => {
    const currentParticipantsIds = (draft.objectParticipant || []).map((participant) => participant.id);
    const valuesIds = values.objectParticipant.map((participant) => participant.value);
    const allIds = Array.from(new Set(currentParticipantsIds.concat(valuesIds))); // 'new Set' to merge without duplicates
    commitMutation({
      mutation: draftEditMutation,
      variables: {
        id: draft.id,
        input: {
          key: 'objectParticipant',
          value: allIds,
        },
      },
      onCompleted: () => {
        setSubmitting(false);
        resetForm();
        handleToggleAddParticipant();
      },
      setSubmitting: undefined,
      onError: undefined,
      optimisticResponse: undefined,
      optimisticUpdater: undefined,
      updater: undefined,
    });
  };

  const assigneeInitialValues: { objectAssignee: FieldOption[] } = { objectAssignee: [] };
  const participantInitialValues: { objectParticipant: FieldOption[] } = { objectParticipant: [] };

  return (
    <>
      <div style={{ height: '100%' }}>
        <Card title={t_i18n('Basic information')}>
          <Grid container={true} spacing={3}>
            <Grid item xs={6}>

              <Label>{t_i18n('Author')}</Label>
              <ItemAuthor createdBy={draft.createdBy} />

              <Label
                sx={{ marginTop: 2 }}
                action={currentAccessRight.canEdit && (
                  <Security needs={[KNOWLEDGE_KNUPDATE]}>
                    <IconButton
                      variant="tertiary"
                      size="small"
                      aria-label={t_i18n('Add new assignees')}
                      title={t_i18n('Add new assignees')}
                      onClick={handleToggleAddAssignee}
                    >
                      <Add fontSize="small" />
                    </IconButton>
                  </Security>
                )}
              >
                {t_i18n('Assignees')}
              </Label>
              <ItemAssignees
                assignees={draft.objectAssignee ?? []}
                stixDomainObjectId={draft.id}
                removeMutation={draftEditMutation}
              />

              <Label
                sx={{ marginTop: 2 }}
                action={(
                  <Security needs={[KNOWLEDGE_KNUPDATE]}>
                    <IconButton
                      variant="tertiary"
                      size="small"
                      aria-label={t_i18n('Add new participants')}
                      title={t_i18n('Add new participants')}
                      onClick={handleToggleAddParticipant}
                    >
                      <Add fontSize="small" />
                    </IconButton>
                  </Security>
                )}
              >
                {t_i18n('Participants')}
              </Label>
              <ItemParticipants
                participants={draft.objectParticipant ?? []}
                stixDomainObjectId={draft.id}
                removeMutation={draftEditMutation}
              />

            </Grid>
          </Grid>
        </Card>
      </div>

      <Formik
        initialValues={assigneeInitialValues}
        onSubmit={onSubmitAssignees}
        onReset={handleToggleAddAssignee}
      >
        {({ submitForm, handleReset }) => (
          <Dialog
            open={openAddAssignee}
            onClose={handleToggleAddAssignee}
            title={t_i18n('Add new assignees')}
          >
            <ObjectAssigneeField
              name="objectAssignee"
              style={fieldSpacingContainerStyle}
            />
            <DialogActions>
              <Button
                variant="secondary"
                onClick={handleReset}
              >
                {t_i18n('Close')}
              </Button>
              <Button
                onClick={submitForm}
              >
                {t_i18n('Add')}
              </Button>
            </DialogActions>
          </Dialog>
        )}
      </Formik>

      <Formik
        initialValues={participantInitialValues}
        onSubmit={onSubmitParticipant}
        onReset={handleToggleAddParticipant}
      >
        {({ submitForm }) => (
          <Dialog
            open={openAddParticipant}
            onClose={handleToggleAddParticipant}
            title={t_i18n('Add new participants')}
          >
            <ObjectParticipantField
              name="objectParticipant"
              style={fieldSpacingContainerStyle}
            />
            <DialogActions>
              <Button
                variant="secondary"
                onClick={handleToggleAddParticipant}
              >
                {t_i18n('Close')}
              </Button>
              <Button
                onClick={submitForm}
              >
                {t_i18n('Add')}
              </Button>
            </DialogActions>
          </Dialog>
        )}
      </Formik>
    </>
  );
};

export default DraftBasicInformation;
