import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import { Field, Form, Formik } from 'formik';
import { graphql } from 'react-relay';
import * as R from 'ramda';
import * as Yup from 'yup';
import { styled } from '@mui/material/styles';
import Drawer from '@mui/material/Drawer';
import Typography from '@mui/material/Typography';
import Button from '@common/button/Button';
import IconButton from '@common/button/IconButton';
import Tooltip from '@mui/material/Tooltip';
import CircularProgress from '@mui/material/CircularProgress';
import { ArrowRightAlt, Close } from '@mui/icons-material';
import { commitMutation, fetchQuery, QueryRenderer } from '../../../../relay/environment';
import inject18n, { isNone } from '../../../../components/i18n';
import withTheme from '../../../../components/withTheme';
import { itemColor } from '../../../../utils/Colors';
import { parse } from '../../../../utils/Time';
import ItemIcon from '../../../../components/ItemIcon';
import SelectFieldFds, { SelectItem } from '../../../../components/fields/SelectFieldFds';
import { truncate } from '../../../../utils/String';
import ObjectMarkingField from '../form/ObjectMarkingField';
import ConfidenceField from '../form/ConfidenceField';
import DateTimePickerField from '../../../../components/DateTimePickerField';
import { fieldSpacingContainerStyle } from '../../../../utils/field';
import { SURFACE_LAYER, fdsLayerClass, layerInputVars } from '../../../../utils/fdsLayer';
import { List, ListItemButton } from '@mui/material';

const Header = styled('div')(({ theme }) => ({
  backgroundColor: theme.palette.background.nav,
  padding: '20px 20px 20px 60px',
}));

const CloseButton = styled(IconButton)({
  '&&': {
    position: 'absolute',
    top: 12,
    left: 5,
    color: 'inherit',
  },
});

const Container = styled('div')({
  padding: '10px 20px 20px 20px',
});

const Item = styled('div')({
  position: 'absolute',
  width: 180,
  height: 80,
  borderRadius: 10,
});

const ItemHeader = styled('div')({
  padding: '10px 0 10px 0',
});

const Icon = styled('div')({
  position: 'absolute',
  top: 8,
  left: 5,
  fontSize: 8,
});

const Type = styled('div')(({ theme }) => ({
  width: '100%',
  textAlign: 'center',
  color: theme.palette.text.primary,
  fontSize: 11,
}));

const Content = styled('div')(({ theme }) => ({
  width: '100%',
  height: 40,
  maxHeight: 40,
  lineHeight: '40px',
  color: theme.palette.text.primary,
  textAlign: 'center',
}));

const Name = styled('span')({
  display: 'inline-block',
  lineHeight: 1,
  fontSize: 12,
  verticalAlign: 'middle',
});

const RelationCreate = styled('div')({
  position: 'relative',
  height: 100,
});

const Middle = styled('div')(({ theme }) => ({
  margin: '0 auto',
  width: 200,
  textAlign: 'center',
  padding: 0,
  color: theme.palette.text.primary,
}));

const Buttons = styled('div')({
  marginTop: 20,
  textAlign: 'right',
});

const relationSx = {
  position: 'relative',
  height: 100,
  transition: 'background-color 0.1s ease',
  cursor: 'pointer',
  '&:hover': {
    background: 'rgba(0, 0, 0, 0.1)',
  },
  padding: '10px',
  marginBottom: '10px',
};

const relationCreationSx = {
  position: 'relative',
  height: 100,
  transition: 'background-color 0.1s ease',
  cursor: 'pointer',
  '&:hover': {
    background: 'rgba(0, 0, 0, 0.1)',
  },
  padding: '10px',
};

const buttonSx = {
  marginLeft: 2,
};

export const stixNestedRefRelationshipCreationResolveQuery = graphql`
  query StixNestedRefRelationshipCreationResolveQuery($id: String!, $toType: String!) {
    stixSchemaRefRelationships(id: $id, toType: $toType) {
      from
      to
    }
  }
`;

export const stixNestedRefRelationshipCreationQuery = graphql`
  query StixNestedRefRelationshipCreationQuery(
    $fromId: StixRef!
    $toId: StixRef!
  ) {
    stixNestedRefRelationships(fromId: $fromId, toId: $toId) {
      edges {
        node {
          id
          parent_types
          entity_type
          relationship_type
          confidence
          start_time
          stop_time
          from {
            ... on BasicObject {
              id
              entity_type
              parent_types
            }
            ... on BasicRelationship {
              id
              entity_type
              parent_types
            }
            ... on StixRefRelationship {
              relationship_type
            }
          }
          to {
            ... on BasicObject {
              id
              entity_type
              parent_types
            }
            ... on BasicRelationship {
              id
              entity_type
              parent_types
            }
            ... on StixCoreRelationship {
              relationship_type
            }
          }
          created_at
          updated_at
          objectMarking {
            id
            definition_type
            definition
            x_opencti_order
            x_opencti_color
          }
        }
      }
    }
  }
`;

const stixNestedRefRelationshipCreationMutation = graphql`
  mutation StixNestedRefRelationshipCreationMutation(
    $input: StixRefRelationshipAddInput!
  ) {
    stixRefRelationshipAdd(input: $input) {
      id
      entity_type
      parent_types
      relationship_type
      confidence
      start_time
      stop_time
      from {
        ... on BasicObject {
          id
          entity_type
          parent_types
        }
        ... on BasicRelationship {
          id
          entity_type
          parent_types
        }
        ... on StixRefRelationship {
          relationship_type
        }
      }
      to {
        ... on BasicObject {
          id
          entity_type
          parent_types
        }
        ... on BasicRelationship {
          id
          entity_type
          parent_types
        }
        ... on StixCoreRelationship {
          relationship_type
        }
      }
      created_at
      updated_at
      created
      objectMarking {
        id
        definition_type
        definition
        x_opencti_order
        x_opencti_color
      }
    }
  }
`;

const stixNestedRefRelationshipValidation = (t) => Yup.object().shape({
  relationship_type: Yup.string().required(t('This field is required')),
  confidence: Yup.number()
    .typeError(t('The value must be a number'))
    .integer(t('The value must be a number')),
  start_time: Yup.date()
    .nullable()
    .default(null)
    .typeError(t('The value must be a datetime (yyyy-MM-dd hh:mm (a|p)m)')),
  stop_time: Yup.date()
    .nullable()
    .default(null)
    .typeError(t('The value must be a datetime (yyyy-MM-dd hh:mm (a|p)m)')),
});

class StixNestedRefRelationshipCreationComponent extends Component {
  constructor(props) {
    super(props);
    this.state = {
      step: 0,
      existingRelations: [],
    };
  }

  onSubmit(values, { setSubmitting, resetForm }) {
    R.forEach((fromObject) => {
      R.forEach((toObject) => {
        const finalValues = R.pipe(
          R.assoc('confidence', parseInt(values.confidence, 10)),
          R.assoc('fromId', fromObject.id),
          R.assoc('toId', toObject.id),
          R.assoc(
            'start_time',
            values.start_time ? parse(values.start_time).format() : null,
          ),
          R.assoc(
            'stop_time',
            values.stop_time ? parse(values.stop_time).format() : null,
          ),
          R.assoc('objectMarking', R.pluck('value', values.objectMarking)),
        )(values);
        commitMutation({
          mutation: stixNestedRefRelationshipCreationMutation,
          variables: {
            input: finalValues,
          },
          setSubmitting,
          onCompleted: (response) => {
            this.props.handleResult(
              response.stixRefRelationshipAdd,
            );
          },
        });
      }, this.props.toObjects);
    }, this.props.fromObjects);
    setSubmitting(false);
    resetForm();
    this.handleClose();
  }

  componentDidUpdate(prevProps) {
    if (
      this.props.open === true
      && this.props.fromObjects !== null
      && this.props.toObjects !== null
      && (prevProps.open !== this.props.open
        || prevProps.fromObjects[0] !== this.props.fromObjects[0]
        || prevProps.toObjects[0] !== this.props.toObjects[0])
    ) {
      if (
        this.props.fromObjects.length === 1
        && this.props.toObjects.length === 1
      ) {
        fetchQuery(stixNestedRefRelationshipCreationQuery, {
          fromId: this.props.fromObjects[0].id,
          toId: this.props.toObjects[0].id,
        })
          .toPromise()
          .then((data) => {
            this.setState({
              step:
                data.stixNestedRefRelationships.edges
                && data.stixNestedRefRelationships.edges.length > 0
                  ? 1
                  : 2,
              existingRelations: data.stixNestedRefRelationships.edges,
            });
          });
      } else {
        this.setState({ step: 2, existingRelations: [] });
      }
    }
  }

  handleSelectRelation(relation) {
    this.props.handleResult(relation);
    this.handleClose();
  }

  handleChangeStep() {
    this.setState({ step: 2 });
  }

  handleReverseRelation() {
    this.setState({ existingRelations: [], step: 0 }, () => this.props.handleReverseRelation());
  }

  handleClose() {
    this.setState({ existingRelations: [], step: 0 });
    this.props.handleClose();
  }

  renderForm(resolveEntityRef, canReverseRelation) {
    const {
      t,
      fromObjects,
      toObjects,
      confidence,
      startTime,
      stopTime,
      defaultMarkingDefinitions,
    } = this.props;
    const relationshipTypes = resolveEntityRef.from;

    const defaultRelationshipType = R.head(relationshipTypes);
    const defaultConfidence = confidence || 15;
    const defaultStartTime = !isNone(startTime) ? startTime : null;
    const defaultEndTime = !isNone(stopTime) ? stopTime : null;
    const initialValues = {
      relationship_type: defaultRelationshipType,
      confidence: defaultConfidence,
      start_time: defaultStartTime,
      stop_time: defaultEndTime,
      objectMarking: defaultMarkingDefinitions
        ? R.map(
            (n) => ({
              label: n.definition,
              value: n.id,
              color: n.x_opencti_color,
            }),
            defaultMarkingDefinitions,
          )
        : [],
    };
    return (
      <Formik
        enableReinitialize={true}
        initialValues={initialValues}
        validationSchema={stixNestedRefRelationshipValidation(t)}
        onSubmit={this.onSubmit.bind(this)}
      >
        {({ submitForm, isSubmitting, setFieldValue }) => (
          <Form>
            <Header>
              <CloseButton
                aria-label="Close"
                onClick={this.handleClose.bind(this)}
              >
                <Close fontSize="small" color="primary" />
              </CloseButton>
              <Typography id="drawer-title" variant="h6">{t('Create a relationship')}</Typography>
            </Header>
            <Container>
              <RelationCreate>
                <Item
                  style={{
                    border: `2px solid ${itemColor(
                      fromObjects[0].entity_type,
                    )}`,
                    top: 10,
                    left: 0,
                  }}
                >
                  <ItemHeader
                    style={{
                      borderBottom: `1px solid ${itemColor(
                        fromObjects[0].entity_type,
                      )}`,
                    }}
                  >
                    <Icon>
                      <ItemIcon
                        type={fromObjects[0].entity_type}
                        color={itemColor(fromObjects[0].entity_type)}
                        size="small"
                      />
                    </Icon>
                    <Type>
                      {fromObjects[0].relationship_type
                        ? t('Relationship')
                        : t(`entity_${fromObjects[0].entity_type}`)}
                    </Type>
                  </ItemHeader>
                  <Content>
                    <Name>
                      { }
                      {fromObjects[0].relationship_type ? (
                        t(`relationship_${fromObjects[0].relationship_type}`)
                      ) : fromObjects.length > 1 ? (
                        <em>{t('Multiple entities selected')}</em>
                      ) : (
                        truncate(fromObjects[0].name, 20)
                      )}
                    </Name>
                  </Content>
                </Item>
                <Middle style={{ paddingTop: 25 }}>
                  <ArrowRightAlt fontSize="large" />
                  <br />
                  {canReverseRelation && (
                    <Button
                      variant="secondary"
                      onClick={this.handleReverseRelation.bind(this)}
                      size="small"
                    >
                      {t('Reverse')}
                    </Button>
                  )}
                </Middle>
                <Item
                  style={{
                    border: `2px solid ${itemColor(toObjects[0].entity_type)}`,
                    top: 10,
                    right: 0,
                  }}
                >
                  <ItemHeader
                    style={{
                      borderBottom: `1px solid ${itemColor(
                        toObjects[0].entity_type,
                      )}`,
                    }}
                  >
                    <Icon>
                      <ItemIcon
                        type={toObjects[0].entity_type}
                        color={itemColor(toObjects[0].entity_type)}
                        size="small"
                      />
                    </Icon>
                    <Type>
                      {toObjects[0].relationship_type
                        ? t('Relationship')
                        : t(`entity_${toObjects[0].entity_type}`)}
                    </Type>
                  </ItemHeader>
                  <Content>
                    <Name>
                      { }
                      {toObjects[0].relationship_type ? (
                        t(`relationship_${toObjects[0].relationship_type}`)
                      ) : toObjects.length > 1 ? (
                        <em>{t('Multiple entities selected')}</em>
                      ) : (
                        truncate(toObjects[0].name, 20)
                      )}
                    </Name>
                  </Content>
                </Item>
              </RelationCreate>
              <Field
                component={SelectFieldFds}
                variant="outlined"
                name="relationship_type"
                label={t('Relationship type')}
                fullWidth={true}
                containerstyle={fieldSpacingContainerStyle}
              >
                {R.map(
                  (type) => (
                    <SelectItem key={type} value={type}>
                      {t(`relationship_${type}`)}
                    </SelectItem>
                  ),
                  relationshipTypes,
                )}
              </Field>
              <ConfidenceField
                containerStyle={fieldSpacingContainerStyle}
              />
              <Field
                component={DateTimePickerField}
                name="start_time"
                textFieldProps={{
                  label: t('Start time'),
                  variant: 'outlined',
                  fullWidth: true,
                  style: { marginTop: 20 },
                }}
              />
              <Field
                component={DateTimePickerField}
                name="stop_time"
                textFieldProps={{
                  label: t('Stop time'),
                  variant: 'outlined',
                  fullWidth: true,
                  style: { marginTop: 20 },
                }}
              />
              <ObjectMarkingField
                name="objectMarking"
                style={fieldSpacingContainerStyle}
                setFieldValue={setFieldValue}
              />
              <Buttons>
                <Button
                  variant="secondary"
                  onClick={this.handleClose.bind(this)}
                  disabled={isSubmitting}
                  sx={buttonSx}
                >
                  {t('Cancel')}
                </Button>
                <Button
                  onClick={submitForm}
                  disabled={isSubmitting}
                  sx={buttonSx}
                >
                  {t('Create')}
                </Button>
              </Buttons>
            </Container>
          </Form>
        )}
      </Formik>
    );
  }

  renderSelectRelation() {
    const { fsd, t, fromObjects, toObjects, theme } = this.props;
    const { existingRelations } = this.state;
    return (
      <div>
        <Header>
          <CloseButton
            aria-label="Close"
            onClick={this.handleClose.bind(this)}
          >
            <Close fontSize="small" color="primary" />
          </CloseButton>
          <Typography id="drawer-title" variant="h6">{t('Select a relationship')}</Typography>
        </Header>
        <List component="div" sx={{ padding: '10px 20px 20px 20px' }}>
          {existingRelations.map((relation) => (
            <ListItemButton
              focusVisibleClassName="focus-visible"
              key={relation.node.id}
              sx={relationSx}
              onClick={this.handleSelectRelation.bind(this, relation.node)}
            >
              <Item
                style={{
                  border: `2px solid ${itemColor(fromObjects[0].entity_type)}`,
                  top: 10,
                  left: 10,
                }}
              >
                <ItemHeader
                  style={{
                    borderBottom: `1px solid ${itemColor(
                      fromObjects[0].entity_type,
                    )}`,
                  }}
                >
                  <Icon>
                    <ItemIcon
                      type={fromObjects[0].entity_type}
                      color={itemColor(fromObjects[0].entity_type)}
                      size="small"
                    />
                  </Icon>
                  <Type>
                    {fromObjects[0].relationship_type
                      ? t('Relationship')
                      : t(`entity_${fromObjects[0].entity_type}`)}
                  </Type>
                </ItemHeader>
                <Content>
                  <Name>
                    {fromObjects.length > 1 ? (
                      <em>{t('Multiple entities selected')}</em>
                    ) : (
                      truncate(fromObjects[0].name, 20)
                    )}
                  </Name>
                </Content>
              </Item>
              <Middle>
                <ArrowRightAlt fontSize="small" />
                <br />
                <Tooltip
                  title={relation.node.description}
                  aria-label="Description"
                  placement="top"
                >
                  <div
                    style={{
                      padding: '5px 8px 5px 8px',
                      backgroundColor: theme.palette.background.accent,
                      color: theme.palette.text.primary,
                      fontSize: 12,
                      display: 'inline-block',
                    }}
                  >
                    {t(`relationship_${relation.node.relationship_type}`)}
                    <br />
                    {t('First obs.')} {fsd(relation.node.start_time)}
                    <br />
                    {t('Last obs.')} {fsd(relation.node.stop_time)}
                  </div>
                </Tooltip>
              </Middle>
              <Item
                style={{
                  border: `2px solid ${itemColor(toObjects[0].entity_type)}`,
                  top: 10,
                  right: 10,
                }}
              >
                <ItemHeader
                  style={{
                    borderBottom: `1px solid ${itemColor(
                      toObjects[0].entity_type,
                    )}`,
                  }}
                >
                  <Icon>
                    <ItemIcon
                      type={toObjects[0].entity_type}
                      color={itemColor(toObjects[0].entity_type)}
                      size="small"
                    />
                  </Icon>
                  <Type>
                    {toObjects[0].relationship_type
                      ? t('Relationship')
                      : t(`entity_${toObjects[0].entity_type}`)}
                  </Type>
                </ItemHeader>
                <Content>
                  <Name>
                    {truncate(toObjects[0].name, 20)}
                  </Name>
                </Content>
              </Item>
              <div className="clearfix" />
            </ListItemButton>
          ))}
          <ListItemButton
            focusVisibleClassName="focus-visible"
            sx={relationCreationSx}
            onClick={this.handleChangeStep.bind(this)}
          >
            <Item
              style={{
                backgroundColor: theme.palette.background.accent,
                top: 10,
                left: 10,
              }}
            >
              <ItemHeader
                style={{
                  borderBottom: '1px solid #ffffff',
                }}
              >
                <Icon>
                  <ItemIcon
                    type={fromObjects[0].entity_type}
                    color="#263238"
                    size="small"
                  />
                </Icon>
                <Type>
                  {t(`entity_${fromObjects[0].entity_type}`)}
                </Type>
              </ItemHeader>
              <Content>
                <Name>
                  {fromObjects.length > 1 ? (
                    <em>{t('Multiple entities selected')}</em>
                  ) : (
                    truncate(fromObjects[0].name)
                  )}
                </Name>
              </Content>
            </Item>
            <Middle style={{ paddingTop: 15 }}>
              <ArrowRightAlt fontSize="small" />
              <br />
              <div
                style={{
                  padding: '5px 8px 5px 8px',
                  backgroundColor: theme.palette.background.accent,
                  color: theme.palette.text.primary,
                  fontSize: 12,
                  display: 'inline-block',
                }}
              >
                {t('Create a nested relationship')}
              </div>
            </Middle>
            <Item
              style={{
                backgroundColor: theme.palette.background.accent,
                top: 10,
                right: 10,
              }}
            >
              <ItemHeader
                style={{
                  borderBottom: '1px solid #ffffff',
                }}
              >
                <Icon>
                  <ItemIcon
                    type={toObjects[0].entity_type}
                    color="#263238"
                    size="small"
                  />
                </Icon>
                <Type>
                  {t(`entity_${toObjects[0].entity_type}`)}
                </Type>
              </ItemHeader>
              <Content>
                <Name>
                  {toObjects.length > 1 ? (
                    <em>{t('Multiple entities selected')}</em>
                  ) : (
                    truncate(toObjects[0].name, 20)
                  )}
                </Name>
              </Content>
            </Item>
            <div className="clearfix" />
          </ListItemButton>
        </List>
      </div>
    );
  }

  renderLoader() {
    return (
      <div style={{ display: 'table', height: '100%', width: '100%' }}>
        <span
          style={{
            display: 'table-cell',
            verticalAlign: 'middle',
            textAlign: 'center',
          }}
        >
          <CircularProgress size={80} thickness={2} />
        </span>
      </div>
    );
  }

  render() {
    const { open, fromObject, toObjects } = this.props;
    const { step } = this.state;
    return (
      <Drawer
        open={open}
        anchor="right"
        variant="temporary"
        elevation={1}
        // This creation drawer mounts MUI's Drawer directly instead of the shared one, so it has to declare its
        // own layer: a drawer is a layer-2 surface and its fields read the layer from the paper.
        slotProps={{
          paper: {
            'aria-labelledby': step > 0 ? 'drawer-title' : undefined,
            'aria-modal': 'true',
            role: 'dialog',
            className: fdsLayerClass(SURFACE_LAYER),
            sx: { ...layerInputVars, minHeight: '100vh', width: '50%', padding: 0 } },
        }}
        sx={{ zIndex: 1202 }}
        onClose={this.handleClose.bind(this)}
      >
        {step === 0
          || step === undefined
          || fromObject === null
          || toObjects === null
          ? this.renderLoader()
          : ''}
        {step === 1 ? this.renderSelectRelation() : ''}
        {step === 2 ? (
          <QueryRenderer
            query={stixNestedRefRelationshipCreationResolveQuery}
            variables={{
              id: this.props.fromObjects[0].id,
              toType: this.props.toObjects[0].entity_type,
            }}
            render={({ props }) => {
              if (props && props.stixSchemaRefRelationships) {
                if (props.stixSchemaRefRelationships.from.length === 0 && props.stixSchemaRefRelationships.to.length > 0) {
                  this.handleReverseRelation();
                  return this.renderLoader();
                }
                return (
                  <div>
                    {this.renderForm(props.stixSchemaRefRelationships, props.stixSchemaRefRelationships.to.length > 0)}
                  </div>
                );
              }
              return this.renderLoader();
            }}
          />
        )
          : ''}
      </Drawer>
    );
  }
}

StixNestedRefRelationshipCreationComponent.propTypes = {
  open: PropTypes.bool,
  fromObjects: PropTypes.array,
  toObjects: PropTypes.array,
  handleResult: PropTypes.func,
  theme: PropTypes.object,
  t: PropTypes.func,
  fsd: PropTypes.func,
  startTime: PropTypes.string,
  stopTime: PropTypes.string,
  confidence: PropTypes.number,
  defaultMarkingDefinitions: PropTypes.array,
  handleClose: PropTypes.func,
  handleReverseRelation: PropTypes.func,
};

export default inject18n(withTheme(StixNestedRefRelationshipCreationComponent));
