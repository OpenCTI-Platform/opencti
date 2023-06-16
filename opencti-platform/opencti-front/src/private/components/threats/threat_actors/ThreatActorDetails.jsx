import React from 'react';
import * as R from 'ramda';
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
import { BullseyeArrow, ArmFlexOutline, DramaMasks, InformationOutline, ArrowUpBoldOutline, ArrowDownBoldOutline } from 'mdi-material-ui';
import ListItemText from '@mui/material/ListItemText';
// Support for Photo Carousel and added Tool Tips
import Carousel from 'react-material-ui-carousel';
import Tooltip from '@mui/material/Tooltip';
import Dialog from '@mui/material/Dialog';
import DialogContentText from '@mui/material/DialogContentText';
import DialogTitle from '@mui/material/DialogTitle';
import DialogContent from '@mui/material/DialogContent';
import DialogActions from '@mui/material/DialogActions';
import Button from '@mui/material/Button';
import { SimpleFileUpload } from 'formik-mui';
import { Formik, Form, Field } from 'formik';
import { CloudUploadOutlined, EditOutlined, CloseOutlined } from '@mui/icons-material';
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

/**
 * @typedef {object} ImageAttributes attributes for uploaded images
 * @property {string} id id for an uploaded image
 * @property {string} name filename for an uploaded image
 * @property {string} comment optional comment describing an uploaded image
 */

/**
 * Returns the storage path for the given image.
 * 
 * @param {ImageAttributes} image
 */
function imagePath(image) {
  return `/storage/view/${image.id}`;
}

function extractFileId(fileRef, sep = '::') {
  const parts = String(fileRef).split(sep);
  return parts[parts.length - 1];
}

function padZero(n, digits = 2) {
  const num = String(n);
  const padLen = digits > num.length ? digits - num.length : 0;
  return R.repeat('0', padLen).concat([num]).join('');
}

class ThreatActorDetailsComponent extends React.Component {
  constructor(props) {
    super(props);
    this.state = {
      showDialog: false,
      open: false,
      /** @type {ImageAttributes[]} */
      images: [],
      editingImageOrder: false,
    };
  }

  componentDidMount() {
    this.resyncImages();
    this.initializeImageState();
  }

  componentDidUpdate() {
    this.resyncImages();
    const { images } = this.state;
    const { threatActor } = this.props;
    if (images.length !== threatActor.x_opencti_photo_refs.length) {
      this.initializeImageState();
    }
  }

  /**
   * Updates threatActor.x_opencti_photo_refs in case photos were added or deleted in the Data tab.
   */
  resyncImages() {
    const { threatActor } = this.props;
    const x_opencti_photo_refs = (threatActor.x_opencti_photo_refs || []).map((ref) => extractFileId(ref));
    const importFiles = threatActor.importFiles?.edges || [];

    if (importFiles.length > 0) {
      const existing_files = importFiles.map((attached_file) => attached_file.node.id);
      const added = existing_files.filter((fileID) => !x_opencti_photo_refs.includes(fileID));
      const deleted = x_opencti_photo_refs.filter((fileID) => !existing_files.includes(fileID));

      if (added.length || deleted.length) {
        // Need to update as photos have been either added or removed on the Data tab.
        // A mutation is called below to correct profile photo list to uploaded photos.
        // The data tab doesn't know about the entity, so syncing actions from that tab is not very straight forward.
        // This approach is a bit of a "workaround" to accommodate for that.
        this.commitPhotoRefs(existing_files, this.initializeImageState);
      }
    } else {
      if (x_opencti_photo_refs.length) {
        this.commitPhotoRefs([], this.updateImageState);
      }
    }
  }

  /**
   * Refreshes image list component state based on latest values in importFiles and x_opencti_photo_refs.
   */
  initializeImageState() {
    const { threatActor, t } = this.props;
    const importFiles = threatActor.importFiles?.edges ?? [];
    const x_opencti_photo_refs = threatActor.x_opencti_photo_refs ?? [];
    if (importFiles.length > 0 && x_opencti_photo_refs.length > 0) {
      /** @type {ImageAttributes[]} */
      const newImages = [];
      x_opencti_photo_refs.forEach((fileId) => {
        const imageFile = importFiles.find((imgFile) => imgFile.node.id === extractFileId(fileId))
        if (imageFile) {
          // Example path: storage/view/import/Threat-Actor/d2d0a901-697c-4e9f-9abd-614349bd6e0c/some_x_photo.png
          newImages.push(
            {
              id: imageFile.node.id,
              name: imageFile.node.name,
              comment: imageFile.node.comment || t('No Comments on Photo'),
            },
          );
        }
      });
      this.updateImageState(newImages);
    }
  }

  /**
   * Updates the images state variable with a new list of images.
   * Will commit to database only if commit = true.
   * 
   * @param {ImageAttributes[]} images 
   * @param {boolean} commit will commit to database if true
   */
  updateImageState(images, commit = false) {
    if (!images) return;
    const { images: sImages } = this.state
    let changed = false;
    if (images.length !== sImages.length) {
      changed = true;
    } else {
      images.forEach((img, i) => {
        if (img.id !== sImages[i].id) {
          changed = true;
        }
      });
    }
    if (changed) {
      this.setState({ images: images }, () => {
        if (commit) {
          this.commitImageState()
        }
      });
    }
  }

  /**
   * Appends an image to the image list stored in component state.
   * 
   * @param {ImageAttributes} image 
   */
  addImage(image) {
    const newImage = {
      ...image,
      comment: image.comment || 'No Comments on Photo',
    };
    this.updateImageState(this.state.images.concat([newImage]));
  }

  handleClickToOpen() {
    this.setState({
      open: true,
      showDialog: true,
    });
  }

  handleToClose() {
    this.setState({
      open: false,
      showDialog: false,
    });
  }

  toggleImageOrderEditing() {
    this.setState({ editingImageOrder: !this.state.editingImageOrder });
  }

  /**
   * Commits the list of images in component state to the database.
   */
  commitImageState() {
    const imageIDs = this.state.images.map((img) => img.id);
    this.commitPhotoRefs(imageIDs);
  }

  /**
   * Updates the list of photo file UUIDs for the threatActor object in the database.
   * 
   * @param {string[]} photoRefs 
   * @param {() => void | null} callback
   */
  commitPhotoRefs(photoRefs, callback = null) {
    const { threatActor } = this.props;
    const photoRefIds = photoRefs.map((photoID, i) => {
      return `${padZero(i)}::${photoID}`;
    });
    commitMutation({
      mutation: threatActorMutationFieldPatch,
      variables: {
        id: threatActor.id,
        input: { key: 'x_opencti_photo_refs', value: photoRefIds, operation: 'replace' },
      },
      onCompleted: callback,
    });
  }

  onSubmit(values, { resetForm, setSubmitting }) {
    this.setState({ open: false });
    this.setState({ showDialog: false });
    const { entityId } = values; // Example: 'd5a32e61-785a-4ef2-9d08-46a5989e363e';
    const x_opencti_photo_refs = values.x_opencti_photo_refs || [];
    const uploadedFile = values.profile_photo;

    commitMutation({
      mutation: fileUploaderWithCommentEntityMutation,
      variables: {
        file: uploadedFile,
        comment: values.x_opencti_photo_ref_comment,
        id: entityId,
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
        this.commitPhotoRefs(x_opencti_photo_refs);
        this.addImage({
          id: fileId,
          name: uploadedFile.name,
          comment: values.x_opencti_photo_ref_comment,
        });

        MESSAGING$.notifySuccess('Photo File successfully uploaded');

        // Reset the modal form, so you can upload another file.
        resetForm();
        setSubmitting(false);
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

  moveImageUp(imageID) {
    const { images } = this.state;
    if (images.length > 0) {
      const targetIndex = images.findIndex((image) => image.id === imageID);
      // Don't move up if index not found or first image
      if (targetIndex <= 0) return;
      const newImages = [].concat(
        images.slice(0, targetIndex - 1),
        images[targetIndex],
        images.slice(targetIndex - 1, targetIndex),
        images.slice(targetIndex + 1),
      );
      this.updateImageState(newImages, true);
    }
  }

  moveImageDown(imageID) {
    const { images } = this.state;
    if (images.length > 0) {
      const targetIndex = images.findIndex((image) => image.id === imageID);
      // Don't move down if index not found or last image
      if (targetIndex === -1 || targetIndex === images.length - 1) return;
      const newImages = [].concat(
        images.slice(0, targetIndex),
        images.slice(targetIndex + 1, targetIndex + 2),
        images[targetIndex],
        images.slice(targetIndex + 2),
      );
      this.updateImageState(newImages, true);
    }
  }

  validationSchema() {
    const SUPPORTED_FORMATS = ['image/bmp', 'image/gif', 'image/jpg', 'image/jpeg', 'image/png'];
    const FILE_SIZE = 10000000;
    return Yup.object({
      profile_photo: Yup.mixed()
        .test('fileSize', 'File size too large, Max file size is 1 Mb', (profile_photo) => (profile_photo ? profile_photo.size <= FILE_SIZE : true))
        .test('fileType', 'Incorrect file type - Only allowed types are bmp, gif, jpg, jpeg, and png ', (profile_photo) => (profile_photo
          ? SUPPORTED_FORMATS.includes(profile_photo.type)
          : true)),
    });
  }

  render() {
    const { t, classes, threatActor, fldt } = this.props;
    const threatActor_id = threatActor.id;
    const threatActor_x_opencti_photo_refs = threatActor.x_opencti_photo_refs;

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
                <Tooltip title={t('Enriching photos of the Threat Actor.')}>
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
                <Tooltip title={t('Information about the photos in the carousel.')}>
                  <InformationOutline fontSize="small" color="primary" />
                </Tooltip>
              </div>
              <div style={{ float: 'left', marginTop: -12 }}>
                <Tooltip
                  title={this.state.editingImageOrder ? t('Toggle editing off') : t('Toggle editing on')}
                  aria-label={`Toggle editing ${this.state.editingImageOrder ? 'off' : 'on'} for photo order`}
                >
                  <IconButton
                    onClick={this.toggleImageOrderEditing.bind(this)}
                    color='primary'
                    size='medium'
                  >
                    {this.state.editingImageOrder ? <CloseOutlined /> : <EditOutlined />}
                  </IconButton>
                </Tooltip>
              </div>
            </Grid>
            <Grid item={true} xs={6}>
              {/* Photo Carousel */}
              <Carousel autoPlay={false} interval={10000}>
                {
                  (this.state.images.length > 0) ?
                    this.state.images.map((item) => (
                      <div style={{ width: '100%', display: 'flex', justifyContent: 'center' }}>
                        <img
                          style={{ backgroundColor: 'white', height: '300px', maxHeight: '300px', width: 'auto' }}
                          alt={item.name}
                          title={item.name}
                          key={item.name}
                          src={imagePath(item)}
                        />
                      </div>
                    ))
                    : <div style={{ width: '100%', display: 'flex', justifyContent: 'center' }}>
                      <img
                        style={{ backgroundColor: 'white', height: '300px', maxHeight: '300px', width: 'auto' }}
                        alt='Placeholder image'
                        title={t('Unknown')}
                        src='/static/ext/silhouettes/Man_Silhouette_clip_art_large.png'
                      />
                    </div>
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
                validationSchema={this.validationSchema()}
              >
                {({
                  submitForm,
                  handleReset,
                  isSubmitting,
                }) => (
                  <Form style={{ margin: '20px 0 20px 0' }}>
                    <input type="hidden" value="{entityId}" name="entityId" />
                    <Dialog open={this.state.showDialog} onClose={this.handleToClose.bind(this)}>
                      <DialogTitle>{t('Add Profile Photo')}</DialogTitle>
                      <DialogContent>
                        <DialogContentText>
                          {t('Select a file to upload and provide a comment to describe it.')}
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
                            marginTop: 20,
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
                      <DialogActions style={{ justifyContent: 'center' }}>
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
                          onClick={submitForm}
                          disabled={isSubmitting}
                          classes={{ root: classes.button }}
                        >
                          {t('Save')}
                        </Button>
                      </DialogActions>
                    </Dialog>
                  </Form>
                )}
              </Formik>
              {/* END - Photo Popup Dialog Form */}

            </Grid>
            <Grid item={true} xs={6} style={{ margin: '-20px 0 0 0' }}>
              {/* Photo Data */}
              {
                (this.state.images.length > 0) ? this.state.images.map((item, i) => (
                  <div style={{ display: 'flex', alignItems: 'center', width: '100%' }}>
                    {(this.state.editingImageOrder) && (<div style={{ flex: '1' }}>
                      {i === 0 ?
                        <Tooltip
                          title={t('The first photo is the primary photo')}
                          placement='left'
                          style={{ padding: '0 auto', width: '100%' }}
                        >
                          <InformationOutline fontSize="small" color="primary" />
                        </Tooltip>
                        :
                        <Tooltip title={t('Move photo up')} placement='left' >
                          <IconButton
                            onClick={() => this.moveImageUp(item.id)}
                            color='primary'
                            size='small'
                            disabled={i === 0}
                          >
                            <ArrowUpBoldOutline />
                          </IconButton>
                        </Tooltip>}
                      <Tooltip title={t('Move photo down')} placement='left' >
                        <IconButton
                          onClick={() => this.moveImageDown(item.id)}
                          color='primary'
                          size='small'
                          disabled={i === this.state.images.length - 1}
                        >
                          <ArrowDownBoldOutline />
                        </IconButton>
                      </Tooltip>
                    </div>)}
                    <pre style={{ flex: 'auto', margin: '5px' }} key={item.name}>{item.name} - {item.comment}</pre>
                  </div>
                ))
                  : <pre>{t('Unknown')} - {t('No known photos of entity have been uploaded')}</pre>
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
