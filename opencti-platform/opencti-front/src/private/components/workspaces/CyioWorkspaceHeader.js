import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import { Formik, Form, Field } from 'formik';
import {
  compose, propOr, filter, append, take,
} from 'ramda';
import graphql from 'babel-plugin-relay/macro';
import { withStyles } from '@material-ui/core/styles';
import AddCircleOutlineIcon from '@material-ui/icons/AddCircleOutline';
import Chip from '@material-ui/core/Chip';
import Typography from '@material-ui/core/Typography';
import ArrowBack from '@material-ui/icons/ArrowBackOutlined';
import IconButton from '@material-ui/core/IconButton';
import Slide from '@material-ui/core/Slide';
import { Add, Close } from '@material-ui/icons';
import { DotsHorizontalCircleOutline } from 'mdi-material-ui';
import Button from '@material-ui/core/Button';
import { commitMutation, MESSAGING$ } from '../../../relay/environment';
import TextField from '../../../components/TextField';
import inject18n from '../../../components/i18n';
import WorkspacePopover from './WorkspacePopover';

const Transition = React.forwardRef((props, ref) => (
  <Slide direction="up" ref={ref} {...props} />
));
Transition.displayName = 'TransitionSlide';

const styles = (theme) => ({
  header: {
    margin: '0 -1.5rem 0 -1.5rem',
    padding: '24px 20px 30px 20px',
    height: '70px',
    backgroundColor: theme.palette.background.paper,
  },
  title: {
    float: 'left',
    textTransform: 'uppercase',
  },
  popover: {
    float: 'left',
    marginTop: '-13px',
  },
  export: {
    float: 'right',
    marginTop: '-13px',
  },
  iconButton: {
    float: 'left',
    minWidth: '0px',
    marginRight: 15,
    marginTop: -4,
    padding: '7px',
  },
  tags: {
    display: 'flex',
    float: 'right',
    marginTop: '-5px',
  },
  tag: {
    marginRight: 7,
  },
  tagsInput: {
    margin: '4px 15px 0 10px',
    float: 'right',
  },
  viewAsField: {
    marginTop: -5,
    float: 'left',
  },
  viewAsFieldTag: {
    margin: '5px 15px 0 0',
    fontSize: 14,
    float: 'left',
  },
});

const workspaceMutation = graphql`
  mutation CyioWorkspaceHeaderFieldMutation($id: ID!, $input: [EditInput]!) {
    workspaceEdit(id: $id) {
      fieldPatch(input: $input) {
        tags
      }
    }
  }
`;

class WorkspaceHeader extends Component {
  constructor(props) {
    super(props);
    this.state = {
      openTag: false,
      openTags: false,
      openTagsCreate: false,
    };
  }

  handleToggleOpenTags() {
    this.setState({ openTags: !this.state.openTags });
  }

  handleToggleCreateTag() {
    this.setState({ openTag: !this.state.openTag });
  }

  getCurrentTags() {
    return this.props.workspace.tags;
  }

  onSubmitCreateTag(element, data, { resetForm }) {
    const currentTags = this.getCurrentTags();
    if (
      (currentTags === null || !currentTags.includes(data.new_tag))
      && data.new_tag !== ''
    ) {
      commitMutation({
        mutation: workspaceMutation,
        variables: {
          id: this.props.workspace.id,
          input: {
            key: 'tags',
            value: append(data.new_tag, currentTags),
          },
        },
        onCompleted: () => MESSAGING$.notifySuccess(this.props.t('The tag has been added')),
      });
    }
    this.setState({ openTag: false });
    resetForm();
  }

  deleteTag(tag) {
    const currentTags = this.getCurrentTags();
    const tags = filter((a) => a !== tag, currentTags);
    commitMutation({
      mutation: workspaceMutation,
      variables: {
        id: this.props.workspace.id,
        input: {
          key: 'tags',
          value: tags,
        },
      },
      onCompleted: () => MESSAGING$.notifySuccess(this.props.t('The tag has been removed')),
    });
  }

  render() {
    const {
      t, classes, workspace, history, handleWidgetCreation,
    } = this.props;
    const tags = propOr([], 'tags', workspace);
    return (
      <div className={classes.header}>
        <Button
          variant="outlined"
          className={classes.iconButton}
          size="large"
          onClick={() => history.goBack()}
        >
          <ArrowBack fontSize="inherit" />
        </Button>
        <Typography
          variant="h1"
          gutterBottom={true}
          classes={{ root: classes.title }}
        >
          {workspace.name}
        </Typography>
        {/* <Security needs={[EXPLORE_EXUPDATE]}> */}
        <div className={classes.popover}>
          <WorkspacePopover id={workspace.id} type={workspace.type} />
        </div>
        {/* </Security> */}
        {/* <div className={classes.export}>
          <ExportButtons domElementId="container" name={workspace.name} />
        </div> */}
        <div className={classes.tags}>
          {take(5, tags).map(
            (tag) => tag.length > 0 && (
              <Chip
                key={tag}
                classes={{ root: classes.tag }}
                label={tag}
                onDelete={this.deleteTag.bind(this, tag)}
              />
            ),
          )}
          {/* <Security needs={[EXPLORE_EXUPDATE]}> */}
          {tags.length > 5 ? (
            <Button
              color="primary"
              aria-tag="More"
              onClick={this.handleToggleOpenTags.bind(this)}
              style={{ fontSize: 14 }}
            >
              <DotsHorizontalCircleOutline />
              &nbsp;&nbsp;{t('More')}
            </Button>
          ) : (
            <div style={{ display: 'flex', alignItems: 'center' }}>
              <IconButton
                style={{ float: 'left', marginTop: -5 }}
                color="secondary"
                aria-tag="Tag"
                onClick={this.handleToggleCreateTag.bind(this)}
              >
                {this.state.openTag ? (
                  <Close fontSize="small" />
                ) : (
                  <Add fontSize="small" />
                )}
              </IconButton>
              {!this.state.openTag && t('New Tag')}
            </div>
          )}
          <Slide
            direction="left"
            in={this.state.openTag}
            mountOnEnter={true}
            unmountOnExit={true}
          >
            <div style={{ float: 'left', marginTop: -5 }}>
              <Formik
                initialValues={{ new_tag: '' }}
                onSubmit={this.onSubmitCreateTag.bind(this, 'main')}
              >
                <Form style={{ float: 'right' }}>
                  <Field
                    component={TextField}
                    name="new_tag"
                    autoFocus={true}
                    placeholder={t('New tag')}
                    className={classes.tagsInput}
                  />
                </Form>
              </Formik>
            </div>
          </Slide>
          <Button
            color='primary'
            aria-tag='More'
            variant='contained'
            onClick={() => handleWidgetCreation()}
            style={{ fontSize: 14, marginLeft: '20px' }}
          >
            <AddCircleOutlineIcon />
            &nbsp;&nbsp;{t('New')}
          </Button>
          {/* </Security> */}
        </div>
        <div className="clearfix" />
      </div>
    );
  }
}

WorkspaceHeader.propTypes = {
  workspace: PropTypes.object,
  classes: PropTypes.object,
  t: PropTypes.func,
  fld: PropTypes.func,
  variant: PropTypes.string,
  handleWidgetCreation: PropTypes.func,
};

export default compose(inject18n, withStyles(styles))(WorkspaceHeader);
