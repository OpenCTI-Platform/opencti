import React, { FunctionComponent } from 'react';
import UserConfidenceLevelField from '@components/settings/users/UserConfidenceLevelField';
import { UserEdition_user$data } from '@components/settings/users/__generated__/UserEdition_user.graphql';
import { Form, Formik } from 'formik';
import Typography from '@mui/material/Typography';
import IconButton from '@mui/material/IconButton';
import { Add } from '@mui/icons-material';
import makeStyles from '@mui/styles/makeStyles';
import { useFormatter } from '../../../../components/i18n';
import { fieldSpacingContainerStyle } from '../../../../utils/field';

const useStyles = makeStyles(() => ({
  createButton: {
    marginTop: '5px',
  },
}));

interface UserEditionConfidenceProps {
  user: UserEdition_user$data;
  context:
  | readonly ({
    readonly focusOn: string | null | undefined;
    readonly name: string;
  } | null)[]
  | null | undefined;
}

const onSubmit = () => {
  console.log('onSubmit');
};

const onFocus = () => {
  console.log('onFocus');
};

const UserEditionConfidence: FunctionComponent<UserEditionConfidenceProps> = ({ user, context }) => {
  const { t_i18n } = useFormatter();
  const classes = useStyles();
  console.log('user', user);
  const initialValues = {
    user_confidence_level_enabled: !!user.user_confidence_level,
    user_confidence_level: user.user_confidence_level?.max_confidence,
  };

  return (
    <>
      <Formik
        enableReinitialize={true}
        initialValues={initialValues}
        onSubmit={() => {}}
      >
        <Form>
          <UserConfidenceLevelField
            name="user_confidence_level"
            label={t_i18n('Max Confidence Level')}
            onFocus={onFocus}
            onSubmit={onSubmit}
            containerStyle={fieldSpacingContainerStyle}
            editContext={context}
            user={user}
          />
        </Form>
      </Formik>
      <Typography variant="h4" gutterBottom={true} style={{ float: 'left', marginTop: '20px' }}>
        {t_i18n('Add a specific max confidence level for an entity type')}
      </Typography>
      <IconButton
        color="primary"
        aria-label="Add"
        onClick={() => console.log('onClick!')}
        classes={{ root: classes.createButton }}
        size="large"
      >
        <Add fontSize="small" />
      </IconButton>
    </>
  );
};

export default UserEditionConfidence;
