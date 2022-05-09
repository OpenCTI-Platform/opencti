import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import { Formik, Form, Field } from 'formik';
import { compose, propOr, filter, append, take } from 'ramda';
import { graphql } from 'react-relay';
import withStyles from '@mui/styles/withStyles';
import Chip from '@mui/material/Chip';
import Typography from '@mui/material/Typography';
import IconButton from '@mui/material/IconButton';
import Slide from '@mui/material/Slide';
import { Add, Close } from '@mui/icons-material';
import { DotsHorizontalCircleOutline } from 'mdi-material-ui';
import Button from '@mui/material/Button';
import { commitMutation, MESSAGING$ } from '../../../relay/environment';
import TextField from '../../../components/TextField';
import inject18n from '../../../components/i18n';
import Security, { EXPLORE_EXUPDATE } from '../../../utils/Security';
import WorkspacePopover from './WorkspacePopover';
import ExportButtons from '../../../components/ExportButtons';

const Transition = React.forwardRef((props, ref) => (
  <Slide direction="up" ref={ref} {...props} />
));
Transition.displayName = 'TransitionSlide';

const styles = () => ({
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
    margin: '-8px 0 0 10px',
  },
  tags: {
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
  mutation WorkspaceHeaderFieldMutation($id: ID!, $input: [EditInput]!) {
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
    const { t, classes, workspace, variant, adjust } = this.props;
    const tags = propOr([], 'tags', workspace);
    return (
      <div style={{ margin: variant === 'dashboard' ? '0 20px 0 20px' : 0 }}>
        <Typography
          variant="h1"
          gutterBottom={true}
          classes={{ root: classes.title }}
        >
          {workspace.name}
        </Typography>
        <Security needs={[EXPLORE_EXUPDATE]}>
          <div className={classes.popover}>
            <WorkspacePopover id={workspace.id} type={workspace.type} />
          </div>
        </Security>
        <div className={classes.export}>
          <ExportButtons
            domElementId="container"
            name={workspace.name}
            adjust={adjust}
          />
        </div>
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
          <Security needs={[EXPLORE_EXUPDATE]}>
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
              <IconButton
                style={{ float: 'left', marginTop: -5 }}
                color="secondary"
                aria-tag="Tag"
                onClick={this.handleToggleCreateTag.bind(this)}
                size="large"
              >
                {this.state.openTag ? (
                  <Close fontSize="small" color="primary" />
                ) : (
                  <Add fontSize="small" />
                )}
              </IconButton>
            )}
          </Security>
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
                    variant="standard"
                    name="new_tag"
                    autoFocus={true}
                    placeholder={t('New tag')}
                    className={classes.tagsInput}
                  />
                </Form>
              </Formik>
            </div>
          </Slide>
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
  adjust: PropTypes.func,
};

export default compose(inject18n, withStyles(styles))(WorkspaceHeader);
