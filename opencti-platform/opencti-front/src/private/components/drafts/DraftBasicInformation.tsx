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
import { graphql } from 'react-relay';
import { FormikHelpers } from 'formik/dist/types';
import ObjectParticipantField from '@components/common/form/ObjectParticipantField';
import { useGetCurrentUserAccessRight } from '../../../utils/authorizedMembers';
import useApiMutation from '../../../utils/hooks/useApiMutation';

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

type Key = 'objectAssignee' | 'objectParticipant';

type DraftFormValuesByKey = {
  objectAssignee: FieldOption[];
  objectParticipant: FieldOption[];
};

type OnSubmit = <K extends Key>(
  key: K,
  values: Pick<DraftFormValuesByKey, K>,
  formikHelpers: FormikHelpers<Pick<DraftFormValuesByKey, K>>,
) => void;

const DraftBasicInformation: FunctionComponent<DraftBasicInformationProps> = ({ draft }) => {
  const { t_i18n } = useFormatter();
  const [commit] = useApiMutation(draftEditMutation);
  const [openAddAssignee, setOpenAddAssignee] = useState(false);
  const [openAddParticipant, setOpenAddParticipant] = useState(false);
  const currentAccessRight = useGetCurrentUserAccessRight(draft.currentUserAccessRight);

  const handleToggleAddAssignee = () => {
    setOpenAddAssignee(!openAddAssignee);
  };

  const handleToggleAddParticipant = () => {
    setOpenAddParticipant(!openAddParticipant);
  };

  const onSubmit: OnSubmit = (key, values, { setSubmitting, resetForm }) => {
    const currentIds = (draft[key] || []).map((assignee) => assignee.id);
    const valuesIds = values[key].map((user) => user.value);
    const allIds = Array.from(new Set(currentIds.concat(valuesIds))); // 'new Set' to merge without duplicates
    commit({
      variables: {
        id: draft.id,
        input: {
          key,
          value: allIds,
        },
      },
      onCompleted: () => {
        setSubmitting(false);
        resetForm();
        if (key === 'objectAssignee') {
          handleToggleAddAssignee();
        } else {
          handleToggleAddParticipant();
        }
      },
    });
  };

  const assigneeInitialValues: Pick<DraftFormValuesByKey, 'objectAssignee'> = { objectAssignee: [] };
  const participantInitialValues: Pick<DraftFormValuesByKey, 'objectParticipant'> = { objectParticipant: [] };

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
        onSubmit={(values, formikHelpers) => onSubmit('objectAssignee', values, formikHelpers)}
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
        onSubmit={(values, formikHelpers) => onSubmit('objectParticipant', values, formikHelpers)}
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
