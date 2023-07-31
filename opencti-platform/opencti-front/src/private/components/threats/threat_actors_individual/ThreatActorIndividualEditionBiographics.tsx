import * as Yup from 'yup';
import { Form, Formik } from 'formik';
import { graphql, useFragment } from 'react-relay';
import { useFormatter } from '../../../../components/i18n';
import { commitMutation, defaultCommitMutation } from '../../../../relay/environment';
import EyeColorField from '../../common/form/mcas/EyeColorField';
import HairColorField from '../../common/form/mcas/HairColorField';
import HeightField from '../../common/form/mcas/HeightField';
import WeightField from '../../common/form/mcas/WeightField';
import { fieldSpacingContainerStyle } from '../../../../utils/field';
import CommitMessage from '../../common/form/CommitMessage';
import { HeightTupleInputValues, WeightTupleInputValues } from './__generated__/ThreatActorIndividualCreationMutation.graphql';
import { ThreatActorIndividualEditionBiographics_ThreatActorIndividual$key } from './__generated__/ThreatActorIndividualEditionBiographics_ThreatActorIndividual.graphql';

const threatActorIndividualEditionBiographicsFocus = graphql`
  mutation ThreatActorIndividualEditionBiographicsFocusMutation(
    $id: ID!
    $input: EditContext!
  ) {
    threatActorIndividualContextPatch(id: $id, input: $input) {
      id
    }
  }
`;

const threatActorIndividualMutationFieldPatch = graphql`
  mutation ThreatActorIndividualEditionBiographicsFieldPatchMutation(
    $id: ID!
    $input: [EditInput]!
  ) {
    threatActorIndividualFieldPatch(id: $id, input: $input) {
      ...ThreatActorIndividualEditionBiographics_ThreatActorIndividual
      ...ThreatActorIndividual_ThreatActorIndividual
    }
  }
`;

const threatActorIndividualEditionBiographicsFragment = graphql`
  fragment ThreatActorIndividualEditionBiographics_ThreatActorIndividual on ThreatActorIndividual {
    id
    x_mcas_eye_color
    x_mcas_hair_color
    x_mcas_height {
      date_seen
      height_in
      height_cm
    }
    x_mcas_weight {
      date_seen
      weight_lb
      weight_kg
    }
  }
`;

const threatActorIndividualValidation = (t: (s: string) => string) => Yup.object().shape({
  x_mcas_eye_color: Yup.string()
    .typeError(t('The value must be a string')),
  x_mcas_hair_color: Yup.string()
    .typeError(t('The value must be a string')),
  x_mcas_weight: Yup.array(),
  x_mcas_height: Yup.array(),
});

interface ThreatActorIndividualEditionBiographicsComponentProps {
  threatActorIndividualRef: ThreatActorIndividualEditionBiographics_ThreatActorIndividual$key,
  enableReferences: boolean,
  context: readonly {
    readonly focusOn: string | null;
    readonly name: string;
  }[] | null | undefined,
}

const ThreatActorIndividualEditionBiographicsComponent:
React.FunctionComponent<ThreatActorIndividualEditionBiographicsComponentProps> = ({
  threatActorIndividualRef,
  enableReferences,
  context,
}: ThreatActorIndividualEditionBiographicsComponentProps) => {
  const { t } = useFormatter();
  const threatActorIndividual = useFragment(threatActorIndividualEditionBiographicsFragment, threatActorIndividualRef);

  const handleChangeFocus = (name: string) => commitMutation({
    ...defaultCommitMutation,
    mutation: threatActorIndividualEditionBiographicsFocus,
    variables: {
      id: threatActorIndividual.id,
      input: {
        focusOn: name,
      },
    },
  });

  const handleSubmitField = (name: string, value: string) => {
    threatActorIndividualValidation(t)
      .validateAt(name, { [name]: value })
      .then(() => {
        commitMutation({
          ...defaultCommitMutation,
          mutation: threatActorIndividualMutationFieldPatch,
          variables: {
            id: threatActorIndividual.id,
            input: { key: name, value },
          },
        });
      })
      .catch(() => false);
  };

  const initialValues = {
    x_mcas_eye_color: threatActorIndividual.x_mcas_eye_color,
    x_mcas_hair_color: threatActorIndividual.x_mcas_hair_color,
    x_mcas_height: threatActorIndividual.x_mcas_height ?? [],
    x_mcas_weight: threatActorIndividual.x_mcas_weight ?? [],
  };

  return (
    <div>
      <Formik
        enableReinitialize={true}
        initialValues={initialValues}
        validationSchema={threatActorIndividualValidation(t)}
        onSubmit={() => {}}
      >
        {({
          submitForm,
          isSubmitting,
          setFieldValue,
          values,
          isValid,
          dirty,
        }) => (
          <div>
            <Form style={{ margin: '20px 0 20px 0' }}>
              <EyeColorField
                name="x_mcas_eye_color"
                label={t('Eye Color')}
                onFocus={handleChangeFocus}
                onChange={handleSubmitField}
                containerStyle={fieldSpacingContainerStyle}
                editContext={context}
                variant="edit"
              />
              <HairColorField
                name="x_mcas_hair_color"
                label={t('Hair Color')}
                onFocus={handleChangeFocus}
                onChange={handleSubmitField}
                containerStyle={fieldSpacingContainerStyle}
                editContext={context}
                variant="edit"
              />
              <HeightField
                name="x_mcas_height"
                values={values.x_mcas_height as HeightTupleInputValues[]}
                id={threatActorIndividual.id}
                label={t('Heights')}
                containerStyle={fieldSpacingContainerStyle}
                editContext={context}
                variant="edit"
              />
              <WeightField
                name="x_mcas_weight"
                values={values.x_mcas_weight as WeightTupleInputValues[]}
                id={threatActorIndividual.id}
                label={t('Weights')}
                containerStyle={fieldSpacingContainerStyle}
                editContext={context}
                variant="edit"
              />
              {enableReferences && (
                <CommitMessage
                  submitForm={submitForm}
                  disabled={isSubmitting || !isValid || !dirty}
                  setFieldValue={setFieldValue}
                  open={false}
                  values={[]}
                  id={threatActorIndividual.id}
                />
              )}
            </Form>
          </div>
        )}
      </Formik>
    </div>
  );
};

export default ThreatActorIndividualEditionBiographicsComponent;
