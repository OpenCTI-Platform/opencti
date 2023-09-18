import * as Yup from 'yup';
import { Form, Formik } from 'formik';
import { graphql, useFragment } from 'react-relay';
import convert from 'convert';
import { useFormatter } from '../../../../components/i18n';
import { commitMutation, defaultCommitMutation } from '../../../../relay/environment';
import HeightField from '../../common/form/mcas/HeightField';
import WeightField from '../../common/form/mcas/WeightField';
import { fieldSpacingContainerStyle } from '../../../../utils/field';
import CommitMessage from '../../common/form/CommitMessage';
import { ThreatActorIndividualEditionBiographics_ThreatActorIndividual$key } from './__generated__/ThreatActorIndividualEditionBiographics_ThreatActorIndividual.graphql';
import OpenVocabField from '../../common/form/OpenVocabField';

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
    eye_color
    hair_color
    height {
      date_seen
      height_cm
    }
    weight {
      date_seen
      weight_kg
    }
  }
`;

const threatActorIndividualValidation = (t: (s: string) => string) => Yup.object().shape({
  eye_color: Yup.string()
    .nullable()
    .typeError(t('The value must be a string')),
  hair_color: Yup.string()
    .nullable()
    .typeError(t('The value must be a string')),
  weight: Yup.array(),
  height: Yup.array(),
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

  const handleSubmitField = (name: string, value: string | string[]) => {
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

  const fullHeights = threatActorIndividual?.height?.map((height) => ({
    height_in: Math.round(convert(Number(height?.height_cm), 'centimeter').to('inch')),
    height_cm: height?.height_cm as number,
    date_seen: height?.date_seen as Date,
  }));

  const fullWeights = threatActorIndividual?.weight?.map((weight) => ({
    weight_lb: Math.round(convert(Number(weight?.weight_kg), 'kilogram').to('pound')),
    weight_kg: weight?.weight_kg as number,
    date_seen: weight?.date_seen as Date,
  }));

  const initialValues = {
    eye_color: threatActorIndividual.eye_color,
    hair_color: threatActorIndividual.hair_color,
    height: fullHeights ?? [],
    weight: fullWeights ?? [],
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
              <OpenVocabField
                name="eye_color"
                label={t('Eye Color')}
                type="eye_color_ov"
                variant="edit"
                onChange={(name, value) => setFieldValue(name, value)}
                onFocus={handleChangeFocus}
                onSubmit={handleSubmitField}
                containerStyle={fieldSpacingContainerStyle}
                multiple={false}
                editContext={context}
              />
              <OpenVocabField
                name="hair_color"
                label={t('Hair Color')}
                type="hair_color_ov"
                variant="edit"
                onChange={(name, value) => setFieldValue(name, value)}
                onFocus={handleChangeFocus}
                onSubmit={handleSubmitField}
                containerStyle={fieldSpacingContainerStyle}
                multiple={false}
                editContext={context}
              />
              <HeightField
                name="height"
                values={values.height}
                id={threatActorIndividual.id}
                label={t('Heights')}
                containerStyle={fieldSpacingContainerStyle}
                editContext={context}
                variant="edit"
              />
              <WeightField
                name="weight"
                values={values.weight}
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
