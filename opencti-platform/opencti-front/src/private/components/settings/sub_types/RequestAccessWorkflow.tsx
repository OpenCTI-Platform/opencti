import { graphql } from 'react-relay';
import React, { FunctionComponent } from 'react';
import Drawer from '@components/common/drawer/Drawer';
import { Form, Formik } from 'formik';
import ObjectParticipantField from '@components/common/form/ObjectParticipantField';
import StatusTemplateField from '@components/common/form/StatusTemplateField';
import { RequestAccessStatusFragment_entitySetting$key } from '@components/settings/sub_types/__generated__/RequestAccessStatusFragment_entitySetting.graphql';
import { useFormatter } from '../../../../components/i18n';
import { fieldSpacingContainerStyle } from '../../../../utils/field';

export const requestAccessWorkflowEditionQuery = graphql`
  query RequestAccessWorkflowEditionQuery($id: String!) {
    entitySetting(id: $id) {
      ...RequestAccessStatusFragment_entitySetting
    }
  }
`;

interface RequestAccessWorkflowProps {
  handleClose: () => void;
  queryRef: RequestAccessStatusFragment_entitySetting$key
  open?: boolean
  workflowId: string,
}

const RequestAccessWorkflow: FunctionComponent<RequestAccessWorkflowProps> = ({
  handleClose,
  open,
}) => {
  const { t_i18n } = useFormatter();
  /*
  const queryData = useFragment(requestAccessFragment, queryRef);
  console.log('queryData', queryData);
  const status = (queryData.requestAccessStatus ?? []).map((n) => ({
    id: n?.id,
    name: n?.name,
    color: n?.color,
  }));
  */
  const initialValues = {
    template: '',
    objectParticipant: [],
  };

  /* console.log('status ==>', status); */
  let makeLintHappy = 0;
  const doMakeLintHappy = () => {
    makeLintHappy += 1;
  };
  return (
    <Drawer
      open={open}
      title={t_i18n('Request Access Workflow')}
      onClose={handleClose}
    >
      <Formik
        initialValues={initialValues}
        onSubmit={() => doMakeLintHappy()}
      >{({ setFieldValue }) => (
        <Form>
          <StatusTemplateField
            name="template"
            setFieldValue={setFieldValue}
            helpertext={`${makeLintHappy}`}
          />
          <ObjectParticipantField
            name="objectParticipant"
            style={fieldSpacingContainerStyle}
            /* onChange={() => console.log('onChange !')} */
          />
        </Form>
      )}
      </Formik>
    </Drawer>
  );
};

export default RequestAccessWorkflow;
