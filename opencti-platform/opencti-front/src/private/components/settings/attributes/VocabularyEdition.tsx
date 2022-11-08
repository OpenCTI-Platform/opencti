import React, { useState } from 'react';
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
import DialogContent from '@mui/material/DialogContent';
import DialogContentText from '@mui/material/DialogContentText';
import DialogActions from '@mui/material/DialogActions';
import Dialog from '@mui/material/Dialog';
import DialogTitle from '@mui/material/DialogTitle';
import { useFormatter } from '../../../../components/i18n';
import { formikFieldToEditInput } from '../../../../utils/utils';
import { Theme } from '../../../../components/Theme';
import {
  useVocabularyCategory_Vocabularynode$data,
} from '../../../../utils/hooks/__generated__/useVocabularyCategory_Vocabularynode.graphql';
import { fieldSpacingContainerStyle } from '../../../../utils/field';
import { MESSAGING$ } from '../../../../relay/environment';
import Transition from '../../../../components/Transition';
import { deleteNode } from '../../../../utils/store';
import { LocalStorage } from '../../../../utils/hooks/useLocalStorage';

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
  mutation VocabularyEditionUpdateMutation(
    $id: ID!
    $category: VocabularyCategory!
    $input: [EditInput!]!
  ) {
    vocabularyFieldPatch(id: $id, category: $category, input: $input){
      ...useVocabularyCategory_Vocabularynode
    }
  }
`;

const vocabularyMutationMerge = graphql`
  mutation VocabularyEditionMergeMutation(
    $fromVocab: VocabularyMergeInput!
    $toId: ID!
  ) {
    vocabularyMerge(fromVocab: $fromVocab, toId: $toId){
      ...useVocabularyCategory_Vocabularynode
    }
  }
`;

const attributeValidation = (t: (s: string) => string) => Yup.object().shape({
  name: Yup.string().required(t('This field is required')),
  description: Yup.string(),
});

interface VocabularyEditionFormikValues {
  name: string,
  description: string,
  aliases: string
}

const VocabularyEdition = ({
  handleClose,
  vocab,
  paginationOptions,
}: { handleClose: () => void, vocab: useVocabularyCategory_Vocabularynode$data, paginationOptions: LocalStorage }) => {
  const { t } = useFormatter();
  const classes = useStyles();

  const [displayMerge, setDisplayMerge] = useState<string>();

  const [commitUpdateMutation] = useMutation(vocabularyMutationUpdate);
  const [commitMergeMutation] = useMutation(vocabularyMutationMerge);

  const submitMerge = (values: VocabularyEditionFormikValues) => {
    commitMergeMutation({
      variables: {
        toId: displayMerge,
        fromVocab: {
          id: vocab.id,
          name: vocab.name,
          aliases: (values.aliases ?? '').split(','),
          description: values.description,
        },
      },
      updater: (store) => deleteNode(store, 'Pagination_vocabularies', paginationOptions, vocab.id),
      onCompleted: () => {
        setDisplayMerge(undefined);
        handleClose();
      },
    });
  };

  const onSubmit: FormikConfig<VocabularyEditionFormikValues>['onSubmit'] = (values, { setSubmitting }) => {
    const input = formikFieldToEditInput({
      ...values,
      aliases: (values.aliases ?? '').split(','),
    }, {
      name: vocab.name,
      aliases: vocab.aliases ?? [],
      description: vocab.description ?? '',
    });
    if (input.length > 0) {
      commitUpdateMutation({
        variables: { id: vocab.id, category: vocab.category.key, input },
        onError: (error) => {
          const { errors } = (error as unknown as { res: { errors: { data: { existingIds: string[], reason: string } }[] } }).res;
          if (errors.at(0)?.data.reason === 'This update will produce a duplicate') {
            setSubmitting(false);
            setDisplayMerge(errors.at(0)?.data.existingIds.at(0));
          } else {
            MESSAGING$.notifyError(errors.at(0)?.data.reason);
          }
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
            aliases: (vocab.aliases ?? []).join(','),
            description: vocab.description ?? '',
          }}
          validationSchema={attributeValidation(t)}
          onSubmit={onSubmit}
        >
          {({ values, submitForm, isSubmitting, setSubmitting }) => (
            <Form style={{ margin: '20px 0 20px 0' }}>
              <Dialog
                PaperProps={{ elevation: 1 }}
                open={Boolean(displayMerge)}
                keepMounted={true}
                TransitionComponent={Transition}
                onClose={() => setDisplayMerge(undefined)}
              >
                <DialogTitle>{t('Another vocabulary has the same name or alias, you must merge them or cancel your update')}</DialogTitle>
                <DialogContent>
                  <DialogContentText>
                    {t('Do you want to merge this vocabulary into the targeted one ?')}
                  </DialogContentText>
                </DialogContent>
                <DialogActions>
                  <Button
                    onClick={() => setDisplayMerge(undefined)}
                  >
                    {t('Cancel')}
                  </Button>
                  <Button
                    color="primary"
                    onClick={() => {
                      setSubmitting(true);
                      submitMerge(values);
                    }}
                    disabled={isSubmitting}
                  >
                    {t('Merge')}
                  </Button>
                </DialogActions>
              </Dialog>
              <Field
                component={TextField}
                variant="standard"
                name="name"
                label={t('Name')}
                fullWidth={true}
                style={fieldSpacingContainerStyle}
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
                component={TextField}
                variant="standard"
                name={'aliases'}
                label={t('Aliases separated by commas')}
                fullWidth={true}
                style={fieldSpacingContainerStyle}
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
