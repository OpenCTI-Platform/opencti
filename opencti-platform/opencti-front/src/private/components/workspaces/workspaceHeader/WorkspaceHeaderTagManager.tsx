import IconButton from '@mui/material/IconButton';
import { DotsHorizontalCircleOutline } from 'mdi-material-ui';
import Tooltip from '@mui/material/Tooltip';
import { CloseOutlined, Delete, LabelOutlined } from '@mui/icons-material';
import React, { useState } from 'react';
import { useFormatter } from 'src/components/i18n';
import { FormikConfig } from 'formik/dist/types';
import { commitMutation, MESSAGING$ } from 'src/relay/environment';
import { graphql } from 'react-relay';
import { SelectChangeEvent } from '@mui/material/Select';
import Slide from '@mui/material/Slide';
import { Field, Form, Formik } from 'formik';
import TextField from '@mui/material/TextField';
import Dialog from '@mui/material/Dialog';
import Transition from 'src/components/Transition';
import { DialogTitle } from '@mui/material';
import DialogContent from '@mui/material/DialogContent';
import List from '@mui/material/List';
import ListItem from '@mui/material/ListItem';
import ListItemText from '@mui/material/ListItemText';
import ListItemSecondaryAction from '@mui/material/ListItemSecondaryAction';
import DialogActions from '@mui/material/DialogActions';
import Button from '@mui/material/Button';
import * as R from 'ramda';
import Chip from '@mui/material/Chip';
import { EXPLORE_EXUPDATE, INVESTIGATION_INUPDATE } from 'src/utils/hooks/useGranted';
import Security from 'src/utils/Security';

const workspaceMutation = graphql`
  mutation WorkspaceHeaderFieldMutation($id: ID!, $input: [EditInput!]!) {
    workspaceFieldPatch(id: $id, input: $input) {
      tags
    }
  }
`;

type WorkspaceHeaderTagManagerProps = {
  tags: string[];
  workspaceId: string;
  canEdit: boolean;
};

export type WorkspaceHeaderTagCreatorFormValues = {
  newTags: string;
};
const WorkspaceHeaderTagManager = ({ tags, workspaceId, canEdit }: WorkspaceHeaderTagManagerProps) => {
  const { t_i18n } = useFormatter();

  const [newTag, setNewTag] = useState<string>('');
  const [isTagInputOpen, setIsTagInputOpen] = useState<boolean>(false);
  const [isTagDialogOpen, setIsTagDialogOpen] = useState<boolean>(false);
  const toggleTagInput = () => setIsTagInputOpen(!isTagInputOpen);
  const toggleTagDialog = () => setIsTagDialogOpen(!isTagDialogOpen);

  const handleChangeNewTag = (event: SelectChangeEvent) => setNewTag(event.target.value);

  const handleManageTags = (tagList: string[], message: string, setSubmitting?: (isSubmitting: boolean) => void) => {
    commitMutation({
      mutation: workspaceMutation,
      variables: {
        id: workspaceId,
        input: {
          key: 'tags',
          value: tagList,
        },
      },
      onCompleted: () => MESSAGING$.notifySuccess(message),
      onError: undefined,
      optimisticResponse: undefined,
      optimisticUpdater: undefined,
      setSubmitting: setSubmitting ?? undefined,
      updater: undefined,
    });
  };
  const deleteTag = (tagToDelete: string) => () => {
    const filteredTags = tags.filter((tag) => tag !== tagToDelete);
    handleManageTags(filteredTags, t_i18n('The tag has been removed'));
  };

  const onSubmitCreateTag: FormikConfig<WorkspaceHeaderTagCreatorFormValues>['onSubmit'] = (data, { resetForm, setSubmitting }) => {
    if (!tags.includes(newTag) && newTag !== '') {
      handleManageTags([...tags, newTag], t_i18n('The tag has been added'), setSubmitting);
    }
    if (isTagInputOpen) toggleTagInput();
    setNewTag('');
    resetForm();
  };

  return (
    <>
      <div style={{ display: 'flex', gap: 7 }}>
        {R.take(2, tags).map(
          (tag) => tag.length > 0 && (
            <Chip
              key={tag}
              label={tag}
              onDelete={deleteTag(tag)}
            />
          ),
        )}
      </div>
      <Security needs={[EXPLORE_EXUPDATE, INVESTIGATION_INUPDATE]} hasAccess={canEdit}>
        {tags.length > 1 ? (
          <IconButton
            color="primary"
            aria-label="More"
            onClick={toggleTagDialog}
            size="medium"
          >
            <DotsHorizontalCircleOutline fontSize="small" />
          </IconButton>
        ) : (
          <Tooltip title={isTagInputOpen ? t_i18n('Cancel') : t_i18n('Add tag')}>
            <IconButton
              color="primary"
              aria-label="Add tag"
              onClick={toggleTagInput}
              size="medium"
            >
              {isTagInputOpen ? (
                <CloseOutlined fontSize="small" />
              ) : (
                <LabelOutlined fontSize="small" />
              )}
            </IconButton>
          </Tooltip>
        )}

        <Slide
          direction="left"
          in={isTagInputOpen}
          mountOnEnter
          unmountOnExit
        >
          <div>
            <Formik
              initialValues={{ new_tag: '' }}
              onSubmit={onSubmitCreateTag}
            >
              <Form>
                <Field
                  component={TextField}
                  variant="standard"
                  name="new_tag"
                  aria-label="tag field"
                  autoFocus
                  placeholder={t_i18n('New tag')}
                  onChange={handleChangeNewTag}
                  value={newTag}
                />
              </Form>
            </Formik>
          </div>
        </Slide>

        <Dialog
          PaperProps={{ elevation: 1 }}
          open={isTagDialogOpen}
          TransitionComponent={Transition}
          onClose={toggleTagDialog}
          fullWidth
        >
          <DialogTitle>
            {t_i18n('Entity tags')}
            <Formik
              initialValues={{ new_tag: '' }}
              onSubmit={onSubmitCreateTag}
            >
              {({ submitForm }) => (
                <Form style={{ float: 'right' }}>
                  <Field
                    component={TextField}
                    variant="standard"
                    name="new_tag"
                    autoFocus={true}
                    placeholder={t_i18n('New tag')}
                    onChange={handleChangeNewTag}
                    value={newTag}
                    onKeyDown={(e) => {
                      if (e.keyCode === 13) return submitForm();
                      return true;
                    }}
                  />
                </Form>
              )}
            </Formik>
          </DialogTitle>
          <DialogContent dividers>
            <List>
              {tags.map(
                (label) => label.length > 0 && (
                <ListItem
                  key={label}
                  disableGutters
                  dense
                >
                  <ListItemText primary={label} />
                  <ListItemSecondaryAction>
                    <IconButton
                      edge="end"
                      aria-label="delete"
                      onClick={deleteTag(label)}
                      size="large"
                    >
                      <Delete />
                    </IconButton>
                  </ListItemSecondaryAction>
                </ListItem>
                ),
              )}
            </List>
          </DialogContent>
          <DialogActions>
            <Button onClick={toggleTagDialog} color="primary">
              {t_i18n('Close')}
            </Button>
          </DialogActions>
        </Dialog>
      </Security>
    </>
  );
};

export default WorkspaceHeaderTagManager;
