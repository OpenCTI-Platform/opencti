import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import * as Yup from 'yup';
import { compose } from 'ramda';
import { graphql, createFragmentContainer } from 'react-relay';
import withStyles from '@mui/styles/withStyles';
import Paper from '@mui/material/Paper';
import Typography from '@mui/material/Typography';
import Grid from '@mui/material/Grid';
import Chip from '@mui/material/Chip';
import List from '@mui/material/List';
import ListItem from '@mui/material/ListItem';
import ListItemIcon from '@mui/material/ListItemIcon';
import { BullseyeArrow, ArmFlexOutline, DramaMasks, InformationOutline } from 'mdi-material-ui';
import ListItemText from '@mui/material/ListItemText';
// Support for Photo Carousel and added Tool Tips
import Carousel from 'react-material-ui-carousel';
import Tooltip from '@mui/material/Tooltip';
import Dialog from '@mui/material/Dialog';
import DialogContentText from '@mui/material/DialogContentText';
import DialogTitle from '@mui/material/DialogTitle';
import DialogContent from '@mui/material/DialogContent';
import Button from '@mui/material/Button';
import { SimpleFileUpload } from 'formik-mui';
import { Formik, Form, Field } from 'formik';
import { CloudUploadOutlined } from '@mui/icons-material';
import IconButton from '@mui/material/IconButton';
import { threatActorMutationFieldPatch } from './ThreatActorEditionDetails';
import ItemOpenVocab from '../../../../components/ItemOpenVocab';
import inject18n from '../../../../components/i18n';
import ExpandableMarkdown from '../../../../components/ExpandableMarkdown';
import MarkdownField from '../../../../components/MarkdownField';
import { commitMutation, MESSAGING$ } from '../../../../relay/environment';

const styles = (theme) => ({
  paper: {
    height: '100%',
    minHeight: '100%',
    margin: '10px 0 0 0',
    padding: '15px',
    borderRadius: 6,
  },
  chip: {
    fontSize: 12,
    lineHeight: '12px',
    backgroundColor: theme.palette.background.accent,
    borderRadius: 5,
    color: theme.palette.text.primary,
    textTransform: 'uppercase',
    margin: '0 5px 5px 0',
  },
});

export const fileUploaderWithCommentEntityMutation = graphql`
  mutation ThreatActorDetailsFileUploaderWithCommentEntityMutation($id: ID!, $file: Upload!, $comment: String) {
    stixCoreObjectEdit(id: $id) {
      importPush(file: $file, comment: $comment) {
        id
        ...FileLine_file
      }
    }
  }
`;
class ThreatActorDetailsComponent extends Component {
  constructor(props) {
    super(props);
    this.state = {
      showDialog: false,
      open: false,
    };
  }

  handleClickToOpen() {
    this.setState({ open: true });
    this.setState({ showDialog: true });
  }

  handleToClose() {
    this.setState({ open: false });
    this.setState({ showDialog: false });
  }

  onSubmit(values, { resetForm }) {
    this.setState({ open: false });
    this.setState({ showDialog: false });
    const { entityId } = values; // 'd5a32e61-785a-4ef2-9d08-46a5989e363e';
    const x_opencti_photo_refs = values.x_opencti_photo_refs || [];
    const uploadedFile = values.profile_photo;

    commitMutation({
      mutation: fileUploaderWithCommentEntityMutation,
      variables: {
        file: uploadedFile,
        comment: values.x_opencti_photo_ref_comment,
        id: entityId,
      },
      optimisticUpdater: () => {
        // setUpload(uploadedFile.name);
      },
      onCompleted: (result) => {
        const fileId = result.stixCoreObjectEdit?.importPush?.id;
        //
        // Add new photo to mcas_photos_refs, if not present
        // (i.e. could be there already and just be a replace of the photo with same name or a comment update)
        //
        if (!x_opencti_photo_refs.includes(fileId)) {
          x_opencti_photo_refs.push(fileId);
        }

        // Call mutation even if photo already in x_opencti_photo_refs, as an update to the record
        // will trigger a redraw of the comments, possibly user was just updating the comment.
        commitMutation({
          mutation: threatActorMutationFieldPatch,
          variables: {
            id: entityId,
            input: { key: 'x_opencti_photo_refs', value: x_opencti_photo_refs, operation: 'replace' },
          },
        });

        MESSAGING$.notifySuccess('Photo File successfully uploaded');

        // Reset the modal form, so you can upload another file.
        resetForm();

        // Reload to show new photos
        window.location.href = `/dashboard/threats/threat_actors/${entityId}`;
      },
      updater: undefined,
      optimisticResponse: undefined,
      onError: undefined,
      setSubmitting: undefined,
    });
  }

  onReset() {
    this.handleToClose();
  }

  render() {
    const { t, classes, threatActor, fldt } = this.props;
    const threatActor_id = threatActor.id;
    const threatActor_x_opencti_photo_refs = threatActor.x_opencti_photo_refs;
    const SUPPORTED_FORMATS = ['image/bmp', 'image/gif', 'image/jpg', 'image/jpeg', 'image/png'];
    const FILE_SIZE = 10000000;
    const validationSchema = Yup.object({
      profile_photo: Yup.mixed()
        .test('fileSize', 'File size too large, Max file size is 1 Mb', (profile_photo) => (profile_photo ? profile_photo.size <= FILE_SIZE : true))
        .test('fileType', 'Incorrect file type - Only allowed types are bmp, gif, jpg, jpeg, and png ', (profile_photo) => (profile_photo
          ? SUPPORTED_FORMATS.includes(profile_photo.type)
          : true)),
    });

    /* Stub to populate Photo Carousel data with an anonymous default photo */
    let images = [
      {
        name: 'Unknown',
        comment: 'No known photos of entity have been uploaded',
        image: '/static/ext/silhouettes/Man_Silhouette_clip_art_large.png',
      },
      // ,
      // {
      //     name: "Default Silhouette",
      //     comment: "Default Silhouette of an Actor",
      //     image: "/static/ext/silhouettes/Female_Silhouette_clip_art_large.png"
      // }
    ];

    if (threatActor.x_opencti_photo_refs !== undefined && threatActor.x_opencti_photo_refs !== null && threatActor.x_opencti_photo_refs.length > 0) {
      const existing_files = [];
      if (threatActor.importFiles !== undefined && threatActor.importFiles !== null
        && threatActor.importFiles.edges !== undefined && threatActor.importFiles.edges !== null
        && threatActor.importFiles.edges.length > 0) {
        const new_images = [];
        threatActor.importFiles.edges.forEach((attached_file) => {
          existing_files.push(attached_file.node.id);
          if (threatActor.x_opencti_photo_refs.includes(attached_file.node.id)) {
            // storage/view/import/Threat-Actor/d2d0a901-697c-4e9f-9abd-614349bd6e0c/some_x_photo.png
            const storage_path = `/storage/view/${attached_file.node.id}`;
            new_images.push(
              {
                name: attached_file.node.name,
                comment: attached_file.node.comment || 'No Comments on Photo',
                image: storage_path,
              },
            );
          }
        });

        if (new_images.length > 0) {
          images = new_images;
        }

        //
        // START - Cleanup for deleted profile data files
        //
        const good_profile_files = [];
        threatActor.x_opencti_photo_refs.forEach((attached_file) => {
          if (existing_files.includes(attached_file)) {
            good_profile_files.push(attached_file);
          }
        });

        if (good_profile_files.length < threatActor.x_opencti_photo_refs.length) {
          // Need to update as photos have been removed on the data tab
          // Call mutation to correct profile photo list to actually available photos.
          // The data tab doesn't know about the entity - so removing on actual remove from that screen is not
          // very straight forward. This approach is a bit of a "workaround" to accommodate for that
          commitMutation({
            mutation: threatActorMutationFieldPatch,
            variables: {
              id: threatActor_id,
              input: { key: 'x_opencti_photo_refs', value: good_profile_files, operation: 'replace' },
            },
          });
        }
        //
        // END - Cleanup for deleted profile data files
        //
      } else {
        // All data object have been deleted, but x_opencti_photo_refs has something in it - clear it out
        commitMutation({
          mutation: threatActorMutationFieldPatch,
          variables: {
            id: threatActor_id,
            input: { key: 'x_opencti_photo_refs', value: [], operation: 'replace' },
          },
        });
        threatActor.x_opencti_photo_refs = [];
      }
    }

    return (
      <div style={{ height: '100%' }}>
        <Typography variant="h4" gutterBottom={true}>
          {t('Details')}
        </Typography>
        <Paper classes={{ root: classes.paper }} variant="outlined">
          <Grid container={true} spacing={3}>
            <Grid item={true} xs={6}>
              <Typography variant="h3" gutterBottom={true} style={{ float: 'left' }}>
                {t('Photo Carousel')}
              </Typography>
              <div style={{ float: 'left', margin: '-3px 0 0 8px' }}>
                <Tooltip
                  title={t(
                    'Enriching photos of the Threat Actor.',
                  )}
                >
                  <InformationOutline fontSize="small" color="primary" />
                </Tooltip>
              </div>
              <div style={{ float: 'left', marginTop: -12 }}>
                <Tooltip title={t('Add a profile photo with comments')} aria-label="Add a photo with comments">
                  <IconButton
                    onClick={this.handleClickToOpen.bind(this)}
                    aria-haspopup="true"
                    color='primary'
                    size='medium'
                  >
                    <CloudUploadOutlined />
                  </IconButton>
                </Tooltip>
              </div>
              <div className="clearfix" />
            </Grid>
            <Grid item={true} xs={6}>
              <Typography variant="h3" gutterBottom={true} style={{ float: 'left' }}>
                {t('Photo Data')}
              </Typography>
              <div style={{ float: 'left', margin: '-3px 0 0 8px' }}>
                <Tooltip
                  title={t(
                    'Data/Information about the photos in the carousel.',
                  )}
                >
                  <InformationOutline fontSize="small" color="primary" />
                </Tooltip>
              </div>
            </Grid>
            <Grid item={true} xs={6}>
              {/* Photo Carousel */}
              <Carousel autoPlay={false} interval={10000}>
                {
                  images.map((item, i) => (
                    <img style={{ backgroundColor: 'white', height: '300px', maxHeight: '300px', width: 'auto' }} title={item.name} key={i} src={item.image} />
                  ))
                }
              </Carousel>

              {/* START - Photo Popup Dialog Form */}
              <Formik
                initialValues={{
                  x_opencti_photo_ref_comment: '',
                  profile_photo: '',
                  entityId: threatActor_id,
                  x_opencti_photo_refs: threatActor_x_opencti_photo_refs,
                }}
                onSubmit={this.onSubmit.bind(this)}
                onReset={this.onReset.bind(this)}
                validationSchema={validationSchema}
              >
                {({
                  submitForm,
                  handleReset,
                  isSubmitting,
                  // setFieldValue,
                  // values,
                }) => (
                  <Form style={{ margin: '20px 0 20px 0' }}>
                    <input type="hidden" value="{entityId}" name="entityId" />
                    <Dialog open={this.state.showDialog} onClose={this.handleToClose.bind(this)}>
                      <DialogTitle>{t('Add Profile Photo')}</DialogTitle>
                      <DialogContent>
                        <DialogContentText>
                          Select a file to upload and provide a comment to describe it. <br />
                        </DialogContentText>
                        <br />
                        <Field
                          component={SimpleFileUpload}
                          name="profile_photo"
                          label={t('File')}
                          FormControlProps={{ style: { width: '100%' } }}
                          InputLabelProps={{ fullWidth: true, variant: 'standard' }}
                          InputProps={{
                            fullWidth: true,
                            variant: 'standard',
                          }}
                          fullWidth={true}
                        />
                        <Field
                          component={MarkdownField}
                          id="x_opencti_photo_ref_comment"
                          name="x_opencti_photo_ref_comment"
                          label={t('Photo Comment')}
                          fullWidth={true}
                          multiline={true}
                          rows="2"
                          style={{ marginTop: 20 }}
                        />
                      </DialogContent>
                      {/* <DialogActions>
                                <Button onClick={onProfilePhotoFormSubmit} color="primary" autoFocus>
                                {t('Save')}
                                </Button>
                                <Button onClick={handleToClose} color="primary" autoFocus>
                                {t('Cancel')}
                                </Button>
                              </DialogActions> */}
                      <div className={classes.buttons} style={{ width: '30%', margin: 'auto', paddingBottom: '10px' }}>
                        <Button
                          variant="contained"
                          onClick={handleReset}
                          disabled={isSubmitting}
                          classes={{ root: classes.button }}
                        >
                          {t('Cancel')}
                        </Button>
                        &nbsp;&nbsp;
                        <Button
                          variant="contained"
                          color="secondary"
                          onClick={submitForm}
                          disabled={isSubmitting}
                          classes={{ root: classes.button }}
                        >
                          {t('Save')}
                        </Button>
                      </div>
                    </Dialog>
                  </Form>
                )}
              </Formik>
              {/* END - Photo Popup Dialog Form */}

            </Grid>
            <Grid item={true} xs={6} style={{ margin: '-20px 0 0 0' }}>
              {/* Photo Data */}
              {
                images.map((item, i) => (
                  <pre key={i}>{item.name} - {item.comment}</pre>
                ))
              }
            </Grid>

            <Grid item={true} xs={6}>
              <Typography variant="h3" gutterBottom={true}>
                {t('Description')}
              </Typography>
              <ExpandableMarkdown
                source={threatActor.description}
                limit={400}
              />
              <Typography
                variant="h3"
                gutterBottom={true}
                style={{ marginTop: 20 }}
              >
                {t('Sophistication')}
              </Typography>
              <ItemOpenVocab
                type="threat-actor-sophistication-ov"
                value={threatActor.sophistication}
              />
              <Typography
                variant="h3"
                gutterBottom={true}
                style={{ marginTop: 20 }}
              >
                {t('Resource level')}
              </Typography>
              <ItemOpenVocab
                type="attack-resource-level-ov"
                value={threatActor.resource_level}
              />
              <Typography
                variant="h3"
                gutterBottom={true}
                style={{ marginTop: 20 }}
              >
                {t('Roles')}
              </Typography>
              {threatActor.roles && (
                <List>
                  {threatActor.roles.map((role) => (
                    <ListItem key={role} dense={true} divider={true}>
                      <ListItemIcon>
                        <DramaMasks />
                      </ListItemIcon>
                      <ListItemText
                        primary={
                          <ItemOpenVocab
                            type="threat-actor-role-ov"
                            value={role}
                          />
                        }
                      />
                    </ListItem>
                  ))}
                </List>
              )}
              <Typography
                variant="h3"
                gutterBottom={true}
                style={{ marginTop: 20 }}
              >
                {t('Goals')}
              </Typography>
              {threatActor.goals && (
                <List>
                  {threatActor.goals.map((goal) => (
                    <ListItem key={goal} dense={true} divider={true}>
                      <ListItemIcon>
                        <BullseyeArrow />
                      </ListItemIcon>
                      <ListItemText primary={goal} />
                    </ListItem>
                  ))}
                </List>
              )}
            </Grid>
            <Grid item={true} xs={6}>
              <Typography variant="h3" gutterBottom={true}>
                {t('Threat actor types')}
              </Typography>
              {threatActor.threat_actor_types
                && threatActor.threat_actor_types.map((threatActorType) => (
                  <Chip
                    key={threatActorType}
                    classes={{ root: classes.chip }}
                    label={threatActorType}
                  />
                ))}
              <Typography
                variant="h3"
                gutterBottom={true}
                style={{ marginTop: 20 }}
              >
                {t('First seen')}
              </Typography>
              {fldt(threatActor.first_seen)}
              <Typography
                variant="h3"
                gutterBottom={true}
                style={{ marginTop: 20 }}
              >
                {t('Last seen')}
              </Typography>
              {fldt(threatActor.last_seen)}
              <Typography
                variant="h3"
                gutterBottom={true}
                style={{ marginTop: 20 }}
              >
                {t('Primary motivation')}
              </Typography>
              <ItemOpenVocab
                type="attack-motivation-ov"
                value={threatActor.primary_motivation}
              />
              <Typography
                variant="h3"
                gutterBottom={true}
                style={{ marginTop: 20 }}
              >
                {t('Secondary motivations')}
              </Typography>
              {threatActor.secondary_motivations && (
                <List>
                  {threatActor.secondary_motivations.map(
                    (secondaryMotivation) => (
                      <ListItem
                        key={secondaryMotivation}
                        dense={true}
                        divider={true}
                      >
                        <ListItemIcon>
                          <ArmFlexOutline />
                        </ListItemIcon>
                        <ListItemText
                          primary={
                            <ItemOpenVocab
                              type="attack-motivation-ov"
                              value={secondaryMotivation}
                            />
                          }
                        />
                      </ListItem>
                    ),
                  )}
                </List>
              )}
            </Grid>
          </Grid>
        </Paper>
      </div>
    );
  }
}

ThreatActorDetailsComponent.propTypes = {
  threatActor: PropTypes.object,
  classes: PropTypes.object,
  t: PropTypes.func,
  fd: PropTypes.func,
};

const ThreatActorDetails = createFragmentContainer(
  ThreatActorDetailsComponent,
  {
    threatActor: graphql`
      fragment ThreatActorDetails_threatActor on ThreatActor {
        id
        first_seen
        last_seen
        description
        threat_actor_types
        sophistication
        resource_level
        primary_motivation
        secondary_motivations
        goals
        roles
        x_opencti_photo_refs
        importFiles(first: 1000) @connection(key: "Pagination_importFiles")
        {
           edges{
             node
              {
                id
                name
                size
                lastModified
                lastModifiedSinceMin
                uploadStatus
                comment
              }
          }
        }
      }
    `,
  },
);

export default compose(inject18n, withStyles(styles))(ThreatActorDetails);
