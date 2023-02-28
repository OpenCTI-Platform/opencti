import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import * as Yup from 'yup';
import { Field, Formik, Form } from 'formik';
import {
  compose, pathOr, assoc, pick, pipe,
} from 'ramda';
import { withStyles } from '@material-ui/core/styles';
import AddIcon from '@material-ui/icons/Add';
import EditIcon from '@material-ui/icons/Edit';
import DeleteIcon from '@material-ui/icons/Delete';
import Typography from '@material-ui/core/Typography';
import { Information } from 'mdi-material-ui';
import Grid from '@material-ui/core/Grid';
import graphql from 'babel-plugin-relay/macro';
import Tooltip from '@material-ui/core/Tooltip';
import Button from '@material-ui/core/Button';
import IconButton from '@material-ui/core/IconButton';
import { Dialog, DialogContent, DialogActions } from '@material-ui/core';
import inject18n from '../../../../components/i18n';
import { truncate } from '../../../../utils/String';
import TextField from '../../../../components/TextField';
import { fetchQuery } from '../../../../relay/environment';
import SelectField from '../../../../components/SelectField';
import MarkDownField from '../../../../components/MarkDownField';
import CyioCoreObjectExternalReferences from '../../analysis/external_references/CyioCoreObjectExternalReferences';

const styles = (theme) => ({
  paper: {
    height: '100%',
    minHeight: '100%',
    margin: '10px 0 0 0',
    padding: '15px',
    borderRadius: 6,
  },
  scrollBg: {
    background: theme.palette.header.background,
    width: '100%',
    color: 'white',
    padding: '10px 5px 10px 15px',
    borderRadius: '5px',
    lineHeight: '20px',
  },
  scrollDiv: {
    width: '100%',
    background: theme.palette.header.background,
    height: '85px',
    overflow: 'hidden',
    overflowY: 'scroll',
  },
  scrollObj: {
    padding: '0px',
    display: 'grid',
    textAlign: 'left',
    alignItems: 'center',
    fontFamily: 'sans-serif',
    color: theme.palette.header.text,
    gridTemplateColumns: '40% 50% 1fr',
  },
  textBase: {
    display: 'flex',
    alignItems: 'center',
    marginBottom: 5,
  },
  inputTextField: {
    color: 'white',
  },
  textField: {
    background: theme.palette.header.background,
  },
  dialogAction: {
    margin: '15px 20px 15px 0',
  },
});

const SystemDocumentationValidation = (t) => Yup.object().shape({
  caption: Yup.string().required(t('This field is required')),
  diagram_link: Yup.string()
    .required(t('This field is required'))
    .url(t('The value must be a valid URL (scheme://host:port/path). For example, https://cyio.darklight.ai')),
});

const SystemDocumentationDiagramQuery = graphql`
query SystemDocumentationDiagramQuery($id: ID!) {
  informationSystem(id: $id) {
    id
    authorization_boundary {
      diagrams {
        entity_type
        description
        caption
        diagram_link
      }
    }
    network_architecture {
      diagrams {
        entity_type
        description
        caption
        diagram_link
       }
    }
    data_flow {
      diagrams {
        entity_type
        description
        caption
        diagram_link
      }
    }
  }
}
`;

class SystemDocumentationDiagram extends Component {
  constructor(props) {
    super(props);
    this.state = {
      open: false,
      openEdit: false,
      selectedDiagram: { diagram: {}, key: null },
      diagram: [],
    };
  }

  componentDidMount() {
    if (this.props.id) {
      fetchQuery(SystemDocumentationDiagramQuery, {
        id: this.props.id,
      })
        .toPromise()
        .then((data) => {
          let diagramData;
          if (this.props.diagramType === 'authorization_boundary') {
            diagramData = pathOr(
              [],
              ['informationSystem', 'authorization_boundary', 'diagrams'],
              data,
            );
          } else if (this.props.diagramType === 'network_architecture') {
            diagramData = pathOr(
              [],
              ['informationSystem', 'network_architecture', 'diagrams'],
              data,
            );
          } else {
            diagramData = pathOr(
              [],
              ['informationSystem', 'data_flow', 'diagrams'],
              data,
            );
          }
          this.setState({
            diagram: [...diagramData],
          });
        });
    }
  }

  onSubmit(values, { resetForm }) {
    this.setState({ open: false, diagram: [...this.state.diagram, values] }, () => (
      this.props.setFieldValue(this.props.name, this.state.diagram)
    ));
    resetForm();
  }

  handleOpenEdit(diagram, key) {
    this.setState({ selectedDiagram: { diagram, key }, openEdit: true });
  }

  handleDeleteDialog(key) {
    this.setState({ diagram: this.state.diagram.filter((value, i) => i !== key) });
  }

  handleCreateDiagram() {
    this.setState({ open: true, selectedDiagram: { diagram: {}, key: null } });
  }

  onEditSubmit(values, { resetForm }) {
    this.state.diagram.splice(this.state.selectedDiagram.key, 1, values);
    this.setState({ diagram: this.state.diagram }, () => (
      this.props.setFieldValue(this.props.name, this.state.diagram)
    ));
    resetForm();
  }

  onReset() {
    this.setState({ open: false, openEdit: false });
  }

  render() {
    const {
      t, classes, title, disabled,
    } = this.props;
    const initialValues = pipe(
      assoc('caption', this.state.selectedDiagram?.diagram?.caption || ''),
      assoc('description', this.state.selectedDiagram?.diagram?.description || ''),
      assoc('diagram_link', this.state.selectedDiagram?.diagram?.diagram_link || ''),
      assoc('entity_type', this.state.selectedDiagram?.diagram?.entity_type || ''),
      pick([
        'caption',
        'description',
        'diagram_link',
        'entity_type',
      ]),
    )(this.state.selectedDiagram?.diagram);
    const {
      diagram,
    } = this.state;
    return (
      <>
        <div style={{ display: 'flex', alignItems: 'center' }}>
          <Typography>
            {title && t(title)}
          </Typography>
          <div style={{ float: 'left', margin: '5px 0 0 5px' }}>
            <Tooltip title={t('Baseline Configuration Name')} >
              <Information fontSize="inherit" color="disabled" />
            </Tooltip>
          </div>
          {!disabled && (
            <IconButton
              size='small'
              onClick={this.handleCreateDiagram.bind(this)}
            >
              <AddIcon fontSize='small' />
            </IconButton>
          )}
        </div>
        <div className='clearfix' />
        <div style={{ display: 'grid', gridTemplateColumns: '40% 1fr', padding: '10px' }}>
          <Typography>
            Caption
          </Typography>
          <Typography>
            Diagram Link
          </Typography>
        </div>
        <div className={classes.scrollBg}>
          <div className={classes.scrollDiv}>
            <div className={classes.scrollObj}>
              {diagram && diagram.map((data, key) => (
                <>
                  <div>{data.caption && data.caption}</div>
                  <div>{data.diagram_link && truncate(data.diagram_link, 35)}</div>
                  {!disabled && (
                    <div style={{ display: 'flex' }}>
                      <IconButton size='small' onClick={this.handleOpenEdit.bind(this, data, key)}>
                        <EditIcon fontSize='small' />
                      </IconButton>
                      <IconButton size='small' onClick={this.handleDeleteDialog.bind(this, key)}>
                        <DeleteIcon fontSize='small' />
                      </IconButton>
                    </div>
                  )}
                </>
              ))
              }
            </div>
          </div>
        </div>
        <Formik
          enableReinitialize={true}
          initialValues={initialValues}
          onReset={this.onReset.bind(this)}
          onSubmit={this.onSubmit.bind(this)}
          validationSchema={SystemDocumentationValidation(t)}
        >
          {({
            submitForm,
            handleReset,
            isSubmitting,
          }) => (
            <Dialog
              open={this.state.open}
              fullWidth={true}
              maxWidth='sm'
            >
              <DialogContent>
                {t('Diagram')}
              </DialogContent>
              <DialogContent style={{ overflowY: 'true' }}>
                <Grid container spacing={3}>
                  <Grid item={true} xs={12}>
                    <div className={classes.textBase}>
                      <Typography
                        variant="h3"
                        color="textSecondary"
                        gutterBottom={true}
                        style={{ margin: 0 }}
                      >
                        {t('Caption')}
                      </Typography>
                      <Tooltip
                        title={t(
                          'Identifies a summary of impact for how the risk affects the system.',
                        )}
                      >
                        <Information style={{ marginLeft: '5px' }} fontSize="inherit" color="disabled" />
                      </Tooltip>
                    </div>
                    <div className="clearfix" />
                    <Field
                      component={TextField}
                      variant='outlined'
                      name="caption"
                      size='small'
                      fullWidth={true}
                    />
                  </Grid>
                  <Grid item={true} xs={12}>
                    <div className={classes.textBase}>
                      <Typography
                        variant="h3"
                        color="textSecondary"
                        gutterBottom={true}
                        style={{ margin: 0 }}
                      >
                        {t('Description')}
                      </Typography>
                      <Tooltip
                        title={t(
                          'Identifies a summary of impact for how the risk affects the system.',
                        )}
                      >
                        <Information style={{ marginLeft: '5px' }} fontSize="inherit" color="disabled" />
                      </Tooltip>
                    </div>
                    <div className="clearfix" />
                    <Field
                      component={MarkDownField}
                      name='description'
                      fullWidth={true}
                      multiline={true}
                      variant='outlined'
                    />
                  </Grid>
                  <Grid item={true} xs={12}>
                    <div className={classes.textBase}>
                      <Typography
                        variant="h3"
                        color="textSecondary"
                        gutterBottom={true}
                        style={{ margin: 0 }}
                      >
                        {t('Add Diagram')}
                      </Typography>
                    </div>
                    <div className="clearfix" />
                    <Field
                      component={TextField}
                      variant='outlined'
                      name="diagram_link"
                      size='small'
                      fullWidth={true}
                    />
                  </Grid>
                  <Grid item={true} xs={12}>
                    <div className={classes.textBase}>
                      <Typography
                        variant="h3"
                        color="textSecondary"
                        gutterBottom={true}
                        style={{ margin: 0 }}
                      >
                        {t('Media Type')}
                      </Typography>
                    </div>
                    <div className="clearfix" />
                    <Field
                      component={SelectField}
                      variant='outlined'
                      name="entity_type"
                      fullWidth={true}
                      style={{ height: '38.09px' }}
                      containerstyle={{ width: '100%' }}
                    />
                  </Grid>
                  <Grid item={true} xs={12}>
                    <CyioCoreObjectExternalReferences
                      disableAdd={true}
                    />
                  </Grid>
                </Grid>
              </DialogContent>
              <DialogActions className={classes.dialogAction}>
                <Button
                  variant='outlined'
                  onClick={handleReset}
                >
                  {t('Cancel')}
                </Button>
                <Button
                  disabled={isSubmitting}
                  variant='contained'
                  onClick={submitForm}
                  color="primary"
                >
                  {t('Submit')}
                </Button>
              </DialogActions>
            </Dialog>
          )}
        </Formik>
        <Formik
          enableReinitialize={true}
          initialValues={initialValues}
          onReset={this.onReset.bind(this)}
          onSubmit={this.onEditSubmit.bind(this)}
          validationSchema={SystemDocumentationValidation(t)}
        >
          {({
            submitForm,
            handleReset,
            isSubmitting,
          }) => (
            <Dialog
              open={this.state.openEdit}
              fullWidth={true}
              maxWidth='sm'
            >
              <DialogContent>
                {t('Diagram')}
              </DialogContent>
              <DialogContent style={{ overflowY: 'true' }}>
                <Grid container spacing={3}>
                  <Grid item={true} xs={12}>
                    <div className={classes.textBase}>
                      <Typography
                        variant="h3"
                        color="textSecondary"
                        gutterBottom={true}
                        style={{ margin: 0 }}
                      >
                        {t('Caption')}
                      </Typography>
                      <Tooltip
                        title={t(
                          'Identifies a summary of impact for how the risk affects the system.',
                        )}
                      >
                        <Information style={{ marginLeft: '5px' }} fontSize="inherit" color="disabled" />
                      </Tooltip>
                    </div>
                    <div className="clearfix" />
                    <Field
                      component={TextField}
                      variant='outlined'
                      name="caption"
                      size='small'
                      fullWidth={true}
                    />
                  </Grid>
                  <Grid item={true} xs={12}>
                    <div className={classes.textBase}>
                      <Typography
                        variant="h3"
                        color="textSecondary"
                        gutterBottom={true}
                        style={{ margin: 0 }}
                      >
                        {t('Description')}
                      </Typography>
                      <Tooltip
                        title={t(
                          'Identifies a summary of impact for how the risk affects the system.',
                        )}
                      >
                        <Information style={{ marginLeft: '5px' }} fontSize="inherit" color="disabled" />
                      </Tooltip>
                    </div>
                    <div className="clearfix" />
                    <Field
                      component={MarkDownField}
                      name='description'
                      fullWidth={true}
                      multiline={true}
                      variant='outlined'
                    />
                  </Grid>
                  <Grid item={true} xs={12}>
                    <div className={classes.textBase}>
                      <Typography
                        variant="h3"
                        color="textSecondary"
                        gutterBottom={true}
                        style={{ margin: 0 }}
                      >
                        {t('Add Diagram')}
                      </Typography>
                    </div>
                    <div className="clearfix" />
                    <Field
                      component={TextField}
                      variant='outlined'
                      name="diagram_link"
                      size='small'
                      fullWidth={true}
                    />
                  </Grid>
                  <Grid item={true} xs={12}>
                    <div className={classes.textBase}>
                      <Typography
                        variant="h3"
                        color="textSecondary"
                        gutterBottom={true}
                        style={{ margin: 0 }}
                      >
                        {t('Media Type')}
                      </Typography>
                    </div>
                    <div className="clearfix" />
                    <Field
                      component={SelectField}
                      variant='outlined'
                      name="entity_type"
                      fullWidth={true}
                      style={{ height: '38.09px' }}
                      containerstyle={{ width: '100%' }}
                    />
                  </Grid>
                  <Grid item={true} xs={12}>
                    <CyioCoreObjectExternalReferences
                      disableAdd={true}
                    />
                  </Grid>
                </Grid>
              </DialogContent>
              <DialogActions className={classes.dialogAction}>
                <Button
                  variant='outlined'
                  onClick={handleReset}
                >
                  {t('Cancel')}
                </Button>
                <Button
                  disabled={isSubmitting}
                  variant='contained'
                  onClick={submitForm}
                  color="primary"
                >
                  {t('Submit')}
                </Button>
              </DialogActions>
            </Dialog>
          )}
        </Formik>
      </>
    );
  }
}

SystemDocumentationDiagram.propTypes = {
  addIcon: PropTypes.bool,
  id: PropTypes.string,
  name: PropTypes.string,
  classes: PropTypes.object,
  disabled: PropTypes.bool,
  t: PropTypes.func,
  fldt: PropTypes.func,
  diagramType: PropTypes.string,
  diagramValues: PropTypes.array,
};

export default compose(inject18n, withStyles(styles))(SystemDocumentationDiagram);
