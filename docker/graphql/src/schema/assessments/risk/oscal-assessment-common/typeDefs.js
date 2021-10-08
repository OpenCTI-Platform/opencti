import gql from 'graphql-tag' ;

const typeDefs = gql`

  "Defines identifying information about an assessment or related process that can be performed. In the assessment plan, this is an intended activity which may be associated with an assessment task. In the assessment results, this an activity that was actually performed as part of an assessment."
  type Activity implements OscalObject {
    # OSCAL Object
    "Uniquely identifies this object."
    id: String!
    "Identifies the type of the Object."
    object_type: String!
    "Indicates the date and time at which the object was originally created."
    created: DateTime!
    "Indicates the date and time that this particular version of the object was last modified.""
    modified: DateTime!
    "Identifies a set of terms used to describe this object. The terms are user-defined or trust-group defined."
    labels: [String]
    "Identifies a list of ExternalReferences, each of which refers to information external to the data model. This property is used to provide one or more URLs, descriptions, or IDs to records in other systems."
    external_references: [ExternalReference]
    "Identifies one or more references to additional commentary on the Model."
    notes: [Note]
    # Activity
    "Identifies the name for the activity."
    name: String!
    "Identifies a human-readable description of the activity."
    description: String!
    # "Identifies one or more steps related to an activity."
    # steps: [Step]
    # "Identifies the optional set of controls and control objectives that are assessed or remediated by this activity."
    # related_controls: [ControlReview]
    "Identifies the person or organization responsible for performing a specific role related to the task."
    responsible_roles: [ResponsibleParty]
  }

  "Defines identifying information about an actor that produces an observation, a finding, or a risk."
  type Actor {
    "Identifies a reference to the tool or person based on the associated type."
    actor: PartyOrComponent!
    "Identifies the kind of actor"
    actor_type: ActorType!
    "For a party, this can optionally be used to specify the role the actor was performing."
    role: OscalResource
    "Identifies a list of ExternalReferences, each of which refers to information external to the data model. This property is used to provide one or more URLs, descriptions, or IDs to records in other systems."
    external_references: [ExternalReference]
  }

  "Defines the identifying information about the system elements being assessed, such as components, inventory items, and locations. In the assessment plan, this identifies a planned assessment subject. In the assessment results this is an actual assessment subject, and reflects any changes from the plan. exactly what will be the focus of this assessment. Any subjects not identified in this way are out-of-scope."
  type AssessmentSubject {
    "Indicates the type of assessment subject, such as a component, inventory, item, location, or party represented by this selection statement."
    subject_type: SubjectType!
    "Identifies a human-readable description of the collection of subjects being included in this assessment."
    description: String
    "Identifies a list of ExternalReferences, each of which refers to information external to the data model. This property is used to provide one or more URLs, descriptions, or IDs to records in other systems."
    external_references: [ExternalReference]
    "Indicates to include all subjects."
    include_all: Boolean!
    "Identifies a set of assessment subjects to include"
    include_subjects: [Subject]
    "Identifies a set of assessment subjects to exclude"
    exclude_subjects: [Subject]
    "Identifies one or more references to additional commentary on the Model."
    notes: [Note]
  }

  "Defines identifying information about an activity to be performed as part of a task."
  type AssociatedActivity {
    "Identifies a references to an activity defined in the list of activities."
    activity: Activity
    "Identifies a list of ExternalReferences, each of which refers to information external to the data model. This property is used to provide one or more URLs, descriptions, or IDs to records in other systems."
    external_references: [ExternalReference]
    "Identifies the person or organization responsible for performing a specific role related to the task."
    responsible_roles: [ResponsibleParty]
    "Identifies an include/exclude pair starts with processing the include, then removing matching entries in the exclude."
    subject: [AssessmentSubject]
    "Identifies one or more references to additional commentary on the Model."
    notes: [Note]
  }

  "Defines identifying information about the containing object from a specific origin."
  type Characterizations {
    "Identifies a list of ExternalReferences, each of which refers to information external to the data model. This property is used to provide one or more URLs, descriptions, or IDs to records in other systems."
    external_references: [ExternalReference]
    "Identifies a reference to tool that performed the detection."
    origins: [Origin]
    "Identifies one or more individual characteristic that is part of a larger set produced by the same actor."
    facets: [Facet]
  }

  interface Component {
    # OSCAL Object
    "Uniquely identifies this object."
    id: String!
    "Identifies the type of the Object."
    object_type: String!
    "Indicates the date and time at which the object was originally created."
    created: DateTime!
    "Indicates the date and time that this particular version of the object was last modified.""
    modified: DateTime!
    "Identifies a set of terms used to describe this object. The terms are user-defined or trust-group defined."
    labels: [String]
    "Identifies a list of ExternalReferences, each of which refers to information external to the data model. This property is used to provide one or more URLs, descriptions, or IDs to records in other systems."
    external_references: [ExternalReference]
    "Identifies one or more references to additional commentary on the Model."
    notes: [Note]
    # Component
    "Indicates the type of the component"
    component_type: ComponentType!
    "Identifies a summary of the technological or business purpose of the component."
    purpose: String
    "Indicates references to one or more roles with responsibility for performing a function relative to the containing object."
    responsible_roles: [ResponsibleParty]
    # TODO:  These SHOULD be references to the entities, not just their UUID/identifier
    #
    # "UUID of the component as it was assigned in the leveraged system's SSP."
    # inherited_uuid: String
    # "UUID of the related leveraged-authorization assembly in this SSP."
    # leveraged_authorization_uuid: String
  }

  "Defines identifying information about an Event Timing that occurs within a date range."
  type DateRangeTiming {
    "Identifies the specified date that the task must occur on or after."
    start_date: DateTime!
    "identifies the specific date that the task must occur on or before."
    end_date: DateTime
  }

  "Defines identifying information about an individual risk response that occurred as part of managing an identified risk."
  type Entry implements OscalObject {
    # OSCAL Object
    "Uniquely identifies this object."
    id: String!
    "Identifies the type of the Object."
    object_type: String!
    "Indicates the date and time at which the object was originally created."
    created: DateTime!
    "Indicates the date and time that this particular version of the object was last modified.""
    modified: DateTime!
    "Identifies a set of terms used to describe this object. The terms are user-defined or trust-group defined."
    labels: [String]
    "Identifies a list of ExternalReferences, each of which refers to information external to the data model. This property is used to provide one or more URLs, descriptions, or IDs to records in other systems."
    external_references: [ExternalReference]
    "Identifies one or more references to additional commentary on the Model."
    notes: [Note]
    # Entry
    "Identifies the type of remediation tracking entry."
    entry_type: [EntryType!]!
    "Identifies the name for the risk log entry."
    name: String!
    "Identifies a human-readable description of of what was done regarding the risk."
    description: String!
    "Identifies the start date and time of the event."
    event_start: DateTime!
    "Identifies the end date and time of the event. If the event is a point in time, the start and end will be the same date and time."
    event_end: DateTime
    "Used to indicate who created a log entry in what role."
    logged_by: [OscalParty]
    "Identifies a change in risk status made resulting from the task described by this risk log entry. This allows the risk's status history to be captured as a sequence of risk log entries."
    status_change: RiskStatus
    "Identifies an individual risk response that this log entry is for."
    related_responses: [RiskResponse]
  }

  "Defines identifying information about evidence relevant to this observation."
  type Evidence {
    "Identifies a resolvable URL reference to the relevant evidence."
    href: URLs
    "Identifies a human-readable description of the evidence."
    description: String
    "Identifies a list of ExternalReferences, each of which refers to information external to the data model. This property is used to provide one or more URLs, descriptions, or IDs to records in other systems."
    external_references: [ExternalReference]
    "Identifies one or more references to additional commentary on the Model."
    notes: [Note]    
  }

  "Defines identifying information about a facet."
  type Facet {
    "Indicates if the facet is 'initial' as first identified, or 'adjusted' indicating that the value has be changed after some adjustments have been made (e.g., to identify residual risk)."
    facet_state: FacetState!
    "Identifies the name of the risk metric within the specified system."
    name: FacetName!
    "Specifies the naming system under which this risk metric is organized, which allows for the same names to be used in different systems controlled by different parties."
    source_system: URL!
    "Indicates the value of the facet."
    value: String!
    "Identifies a list of ExternalReferences, each of which refers to information external to the data model. This property is used to provide one or more URLs, descriptions, or IDs to records in other systems."
    external_references: [ExternalReference]
    "Identifies one or more references to additional commentary on the Model."
    notes: [Note]    
  }

  "Defines identifying information about an individual finding."
  type Finding implements OscalObject {
    # OSCAL Object
    "Uniquely identifies this object."
    id: String!
    "Identifies the type of the Object."
    object_type: String!
    "Indicates the date and time at which the object was originally created."
    created: DateTime!
    "Indicates the date and time that this particular version of the object was last modified.""
    modified: DateTime!
    "Identifies a set of terms used to describe this object. The terms are user-defined or trust-group defined."
    labels: [String]
    "Identifies a list of ExternalReferences, each of which refers to information external to the data model. This property is used to provide one or more URLs, descriptions, or IDs to records in other systems."
    external_references: [ExternalReference]
    "Identifies one or more references to additional commentary on the Model."
    notes: [Note]
    # Finding
    "Identifies the name for the finding."
    name: String!
    "Identifies a human-readable description of the finding."
    description: String!
    "Identifies one or more sources of the finding, such as a tool, interviewed person, or activity."
    origins: [Origin]
    # "Identifies an assessor's conclusions regarding the degree to which an objective is satisfied."
    # target: FindingTarget
    # "Identifies a reference to the implementation statement in the SSP to which this finding is related."
    # implementation_statement: ImplementationStatement
    "Relates the finding to a set of referenced observations that were used to determine the finding."
    related_observations: [Observation]
    "Relates the finding to a set of referenced risks that were used to determine the finding."
    related_risks: [Risk]
  }

  "Defines identifying information about the target of a finding."
  type FindingTarget {
    target_type: FindingTargetType!
    target: StatementOrObjective!
    name: String
    description: String
    external_references: [ExternalReference]
    "Identifies whether the objective is satisfied or not within a given system."
    objective_status_state: ObjectiveStatusState!
    "Identifies the reason the objective was given it's status."
    objective_status_reason: ObjectiveStatusReason
    "Identifies an explanation as to why the objective was not satisfied."
    objective_status_explanation: String
    "Indicates the degree to which the given control was implemented."
    implementation_status: ImplementationStatus
    "Identifies one or more references to additional commentary on the Model."
    notes: [Note]
  }

  "Defines identifying information about a single managed inventory item within the system."
  interface InventoryItem {
    # OSCAL Object
    "Uniquely identifies this object."
    id: String!
    "Identifies the type of the Object."
    object_type: String!
    "Indicates the date and time at which the object was originally created."
    created: DateTime!
    "Indicates the date and time that this particular version of the object was last modified.""
    modified: DateTime!
    "Identifies a set of terms used to describe this object. The terms are user-defined or trust-group defined."
    labels: [String]
    "Identifies a list of ExternalReferences, each of which refers to information external to the data model. This property is used to provide one or more URLs, descriptions, or IDs to records in other systems."
    external_references: [ExternalReference]
    "Identifies one or more references to additional commentary on the Model."
    notes: [Note]
    # Inventory Item
    "Identifies one or more references to a set of organizations or persons that have responsibility for performing a referenced role in the context of the containing object."
    responsible_parties: [ResponsibleParty]
    "Identifies the set of components that are implemented in a given system inventory item."
    implemented_components: [Component]
  }

  "Defines identifying information about a mitigation facctor."
  type MitigatingFactor implements OscalObject {
    # OSCAL Object
    "Uniquely identifies this object."
    id: String!
    "Identifies the type of the Object."
    object_type: String!
    "Indicates the date and time at which the object was originally created."
    created: DateTime!
    "Indicates the date and time that this particular version of the object was last modified.""
    modified: DateTime!
    "Identifies a set of terms used to describe this object. The terms are user-defined or trust-group defined."
    labels: [String]
    "Identifies a list of ExternalReferences, each of which refers to information external to the data model. This property is used to provide one or more URLs, descriptions, or IDs to records in other systems."
    external_references: [ExternalReference]
    "Identifies one or more references to additional commentary on the Model."
    notes: [Note]
    # Mitigating Factor
    # "Identifies a reference to an implementation statement in the SSP."
    # implementation_statement: ImplementationStatement
    "Identifies a human-readable description of this mitigating factor."
    description: String
    "Identifies a list of ExternalReferences, each of which refers to information external to the data model. This property is used to provide one or more URLs, descriptions, or IDs to records in other systems."
    external_references: [ExternalReference]
    "Identifies a reference to one or more subjects of the observations.  The subject indicates what was observed, who was interviewed, or what was tested or inspected."
    subjects: [Subject]
  }

  "Defines identifying information about an observation."
  type Observation implements OscalObject {
    # OSCAL Object
    "Uniquely identifies this object."
    id: String!
    "Identifies the type of the Object."
    object_type: String!
    "Indicates the date and time at which the object was originally created."
    created: DateTime!
    "Indicates the date and time that this particular version of the object was last modified.""
    modified: DateTime!
    "Identifies a set of terms used to describe this object. The terms are user-defined or trust-group defined."
    labels: [String]
    "Identifies a list of ExternalReferences, each of which refers to information external to the data model. This property is used to provide one or more URLs, descriptions, or IDs to records in other systems."
    external_references: [ExternalReference]
    "Identifies one or more references to additional commentary on the Model."
    notes: [Note]
    # Observation
    "Identifies the name for the observation."
    name: String!
    "Identifies a human-readable description of the assessment observation."
    description: String!
    "Identifies how the observation was made."
    methods: MethodTypes!
    "Identifies the nature of the observation. More than one may be used to further qualify and enable filtering."
    observation_types: [ObservationType]
    "Identifies one or more sources of the finding, such as a tool, interviewed person, or activity."
    origins: [Origin]
    "Identifies a reference to one or more subjects of the observations.  The subject indicates what was observed, who was interviewed, or what was tested or inspected."
    subjects: [Subject]
    "Identifies relevant evidence collected as part of this observation."
    relevant_evidence: [Evidence]
    "Identifies a Date/time stamp identifying when the finding information was collected."
    collected: DateTime!
    "Identifies Date/time identifying when the finding information is out-of-date and no longer valid. Typically used with continuous assessment scenarios."
    expires: DateTime
  }

  "Defines identifying information about an Event Timing that occur on a specific date."
  type OnDateTiming {
    "Identifies the date that the task must occur on."
    on_date: DateTime!
  }

  "Defines identifying information about the source of the finding, such as a tool, interviewed person, or activity."
  type Origin {
    "Identifies one or more actors that produces an observation, a finding, or a risk. One or more actor type can be used to specify a person that is using a tool."
    origin_actors: [Actor!]!
    " Identifies one or more task for which the containing object is a consequence of."
    related_tasks: [RelatedTask]
  }

  "Defines identifying information about an asset required to achieve remediation."
  type RequiredAsset implements OscalObject {
    # OSCAL Object
    "Uniquely identifies this object."
    id: String!
    "Identifies the type of the Object."
    object_type: String!
    "Indicates the date and time at which the object was originally created."
    created: DateTime!
    "Indicates the date and time that this particular version of the object was last modified.""
    modified: DateTime!
    "Identifies a set of terms used to describe this object. The terms are user-defined or trust-group defined."
    labels: [String]
    "Identifies a list of ExternalReferences, each of which refers to information external to the data model. This property is used to provide one or more URLs, descriptions, or IDs to records in other systems."
    external_references: [ExternalReference]
    "Identifies one or more references to additional commentary on the Model."
    notes: [Note]
    # Required Asset
    "Identifies a reference to one or more subjects, in the form of a party or tool required to achieve the remediation."
    subjects: [Subject]
    "Identifies the name of the required asset."
    name: String!
    "Identifies a human-readable description of the required asset."
    description: String!
  }

  "Defines identifying information about a Risk"
  type Risk implements OscalObject {
    # OSCAL Object
    "Uniquely identifies this object."
    id: String!
    "Identifies the type of the Object."
    object_type: String!
    "Indicates the date and time at which the object was originally created."
    created: DateTime!
    "Indicates the date and time that this particular version of the object was last modified.""
    modified: DateTime!
    "Identifies a set of terms used to describe this object. The terms are user-defined or trust-group defined."
    labels: [String]
    "Identifies a list of ExternalReferences, each of which refers to information external to the data model. This property is used to provide one or more URLs, descriptions, or IDs to records in other systems."
    external_references: [ExternalReference]
    "Identifies one or more references to additional commentary on the Model."
    notes: [Note]
    # Risk
    "Identifies the name for the risk."
    name: String!
    "Identifies a human-readable summary of the identified risk, to include a statement of how the risk impacts the system."
    description: String!
    "Identifies a summary of impact for how the risk affects the system."
    statement: String!
    "Identifies the status of the associated risk."
    risk_status: RiskStatus!
    "Identifies one or more sources of the finding, such as a tool, interviewed person, or activity."
    origins: [Origin]
    "Identifies a reference to one or more externally-defined threats."
    threats: [ThreatReference]
    "Identifies a collection of descriptive data about the containing object from a specific origin."
    characterizations: [Characterization]
    "Identifies one or more existing mitigating factors that may affect the overall determination of the risk, with an optional link to an implementation statement in the SSP."
    mitigating_factors: [MitigatingFactor]
    "Identifies the date/time by which the risk must be resolved."
    deadline: DateTime
    "Identifies either recommended or an actual plan for addressing the risk."
    remediations: [RiskResponse]
    "log of all risk-related tasks taken."
    risk_log: [Entry]
    "Relates the finding to a set of referenced observations that were used to determine the risk.  This would be the Component in which the risk exists and the InventoryItem(s) in which theComponent is installed"
    related_observations: [Observation]
    "Identifies that the risk has been confirmed to be a false positive."
    false_positive: RiskAssertionState
    "Identifies that the risk cannot be remediated without impact to the system and must be accepted."
    accepted: RiskAssertionState
    "Identifies that mitigating factors were identified or implemented, reducing the likelihood or impact of the risk."
    risk_adjusted: RiskAssertionState
    "Identifies Assessor's recommended risk priority. Lower numbers are higher priority. One (1) is highest priority."
    priority: PositiveInteger
    "Identifies that a vendor resolution is pending, but not yet available."
    vendor_dependency: RiskAssertionState
    "Identifies a control impacted by this risk."
    impacted_control_id: String
  }

  "Defines identifying information about a response to a risk."
  type RiskResponse implements OscalObject {
    # OSCAL Object
    "Uniquely identifies this object."
    id: String!
    "Identifies the type of the Object."
    object_type: String!
    "Indicates the date and time at which the object was originally created."
    created: DateTime!
    "Indicates the date and time that this particular version of the object was last modified.""
    modified: DateTime!
    "Identifies a set of terms used to describe this object. The terms are user-defined or trust-group defined."
    labels: [String]
    "Identifies a list of ExternalReferences, each of which refers to information external to the data model. This property is used to provide one or more URLs, descriptions, or IDs to records in other systems."
    external_references: [ExternalReference]
    "Identifies one or more references to additional commentary on the Model."
    notes: [Note]
    # Risk Response
    "Identifies the type of response to the risk"
    response_type: ResponseType!
    "Identifies whether this is a recommendation, such as from an assessor or tool, or an actual plan accepted by the system owner."
    lifecycle: RiskLifeCyclePhase!
    "Identifies the name for the response activity."
    name: String!
    "Identifies a human-readable description of the response plan."
    description: String!
    "Identifies one or more sources of individuals and/or tools that generated this recommended or planned response."
    origins: [Origin]
    "Identifies an asset required to achieve remediation."
    required_assets: [RequiredAsset]
    "Identifies one or more scheduled events or milestones, which may be associated with a series of assessment actions."
    tasks: [Task]
  }

  "Defines the identifying information about a resource. Use type to indicate whether the identified resource is a component, inventory item, location, user, or something else."
  type Subject {
    "Identifies a reference to a component, inventory-item, location, party, user, or resource."
    subject: SubjectTarget
    "Indicates the type of subject"
    subject_type: SubjectType!
    "Identifies the name for the referenced subject."
    name: String!
    "Identifies a list of ExternalReferences, each of which refers to information external to the data model. This property is used to provide one or more URLs, descriptions, or IDs to records in other systems."
    external_references: [ExternalReference]
    "Identifies one or more references to additional commentary on the Model."
    notes: [Note]
  }

  "Defines identifying information about a scheduled event or milestone, which may be associated with a series of assessment actions."
  type Task implements OscalObject {
    # OSCAL Object
    "Uniquely identifies this object."
    id: String!
    "Identifies the type of the Object."
    object_type: String!
    "Indicates the date and time at which the object was originally created."
    created: DateTime!
    "Indicates the date and time that this particular version of the object was last modified.""
    modified: DateTime!
    "Identifies a set of terms used to describe this object. The terms are user-defined or trust-group defined."
    labels: [String]
    "Identifies a list of ExternalReferences, each of which refers to information external to the data model. This property is used to provide one or more URLs, descriptions, or IDs to records in other systems."
    external_references: [ExternalReference]
    "Identifies one or more references to additional commentary on the Model."
    notes: [Note]
    # Task
    "Identifies the type of task."
    task_type: TaskType!
    "Identifies the name for the task."
    name: String!
    "Identifies a human-readable description of the task."
    description: String!
    "Identifies the timing under which the task is intended to occur."
    timing: EventTiming
    "Identifies that the task is dependent on another task."
    task_dependencies: [Task]
    ""
    tasks: [Task]
    "Identifies an individual activity to be performed as part of a task."
    associated_activities: [AssociatedActivity]
    "Identifies a reference to one or more subjects that the task is performed against: component, inventory item, party, users"
    subjects: [AssessmentSubject]
    "Identifies the person or organization responsible for performing a specific role related to the task."
    responsible_roles: [ResponsibleParty]
  }

  "Defines identifying information about a reference to a threat."
  type ThreatReference {
    "Identifies the source of the threat information."
    source_system: URL!
    "Identifies an optional location for the threat data, from which this ID originates."
    href: URL
    "Identifies the specific identifier associated with the threat."
    threat_identifier: URL
  }

  union EventTiming = DateRangeTiming | OnDateTiming
  union PartyOrComponent = OscalParty | Component
  # union StatementOrObjects = ControlStatement | ControlObjective
  union SubjectTarget = Component | InventoryItem | OscalLocation | OscalParty | SystemUser | OscalResource

  "Defines the types of actors"
  enum ActorType {
    "A reference to a tool component defined with the assessment assets."
    tool
    "A reference to an assessment-platform defined with the assessment assets."
    assessment_platform
    "A reference to an assessment-platform defined with the assessment assets."
    party
  }

  "Defines the types of components"
  enum ComponentType {
    "Any guideline or recommendation."
    guidance
    "A physical device."
    hardware
    "A connection to something outside this system."
    interconnection
    "A physical or virtual network."
    network
    "A tangible asset used to provide physical protections or countermeasures."
    physical
    "An applicable plan."
    plan
    "An enforceable policy."
    policy
    "A list of steps or actions to take to achieve some end result."
    process_procedure
    " A service that may provide APIs."
    service
    "Any software, operating system, or firmware."
    software
    "Any organizational or industry standard."
    standard
    "An external system, which may be a leveraged system or the other side of an interconnection."
    system
    "The system as a whole."
    this_system
    "An external assessment performed on some other component, that has been validated by a third-party."
    validation

  }

  "Defines the type of remediation tracking entry. Can be multi-valued."
  enum EntryType {
    "Contacted vendor to determine the status of a pending fix to a known vulnerability."
    vendor_check_in
    "Information related to the current state of response to this risk."
    status_update
    "A significant step in the response plan has been achieved."
    milestone_complete
    "An activity was completed that reduces the likelihood or impact of this risk."
    mitigation
    "An activity was completed that eliminates the likelihood or impact of this risk."
    remediated
    "The risk is no longer applicable to the system."
    closed
    "A deviation request was made to the authorizing official."
    dr_submission
    "A previously submitted deviation request has been modified."
    dr_updated
    "The authorizing official approved the deviation."
    dr_approved
    "The authorizing official rejected the deviation."
    dr_rejected
  }

  "Defines the states of a facet"
  enum FacetState {
    "As first identified."
    initial
    "Indicates that residual risk remains after some adjustments have been made."
    adjusted
  }

  "Identifies the implementation status of the control or control objective."
  enum ImplementationStatus {
    "The control is fully implemented."
    implemented
    "The control is partially implemented."
    partial
    "There is a plan for implementing the control as explained in the remarks."
    planned
    "There is a plan for implementing the control as explained in the remarks."
    alternative
    "This control does not apply to this system as justified in the remarks."
    not_applicable
  }

  "Defined the types of methods for making an observation."
  enum MethodTypes {
    "An inspection was performed."
    EXAMINE
    "An interview was performed."
    INTERVIEW
    "A manual or automated test was performed."
    TEST
  }

  "Defines the reasons for the objective status"
  enum ObjectiveStatusReason {
    "The target system or system component satisfied all the conditions."
    pass
    "The target system or system component did not satisfy all the conditions."
    fail
    "The target system or system component did not satisfy all the conditions."
    other
  }

  "Defines the states of the objective status"
  enum ObjectiveStatusState {
    "The objective has been completely satisfied"
    satisfied
    "The objective has not been completely satisfied, but may be partially satisfied"
    not_satisfied
  }

  "Defines the types of observations"
  enum ObservationType {
    "Identifies the nature of the observation. More than one may be used to further qualify and enable filtering."
    ssp_statement_issue
    "An observation about the status of a the associated control objective."
    control_objective
    "A mitigating factor was identified."
    mitigation
    "An assessment finding. Used for observations made by tools, penetration testing, and other means."
    finding
    "An observation from a past assessment, which was converted to OSCAL at a later date."
    historic
  }

  "Defines the states of a risk assertion"
  enum RiskAssertionState {
    "Investigating assertion"
    investigating
    "Pending assertion decision"
    pending
    "Assertion approved"
    approved
    "Assertion withdrawn"
    withdrawn
  }

  "Defines the types of risk responses"
  enum ResponseType {
    "The risk will be eliminated."
    avoid
    "The risk will be reduced."
    mitigate
    "The risk will be transferred to another organization or entity."
    transfer
    "The risk will continue to exist without further efforts to address it. (Sometimes referred to as 'Operationally required')"
    accept
    "The risk will be partially transferred to another organization or entity."
    share
    "Plans will be made to address the risk impact if the risk occurs. (This is a form of mitigation.)"
    contingency
    "No response, such as when the identified risk is found to be a false positive."
    none
  }

  "Defines the set of phase of the risk lifecycle."
  enum RiskLifeCyclePhase {
    "Recommended Remediation"
    recommendation
    "The actions intended to resolve the risk."
    planned
    "This remediation activities were performed to address the risk."
    completed
  }

  "Defines the type of status for a risk"
  enum RiskStatus {
    "The risk has been identified."
    open
    "The identified risk is being investigated. (Open risk)"
    investigating
    "Remediation activities are underway, but are not yet complete. (Open risk)"
    remediating
    "A risk deviation, such as false positive, risk reduction, or operational requirement has been submitted for approval. (Open risk)"
    deviation-requested
    "A risk deviation, such as false positive, risk reduction, or operational requirement has been approved. (Open risk)"
    deviation-approved
    "The risk has been resolved."
    closed
  }

  "Defines the type of tasks"
  enum TaskType {
    "The task represents a planned milestone."
    milestone
    "The task represents a specific assessment action to be performed."
    action
  }

  "Defines types of subjects"
  enum SubjectType {
    " Component"
    component
    "Inventory Item"
    inventory_item
    "Location"
    location
    "Interview Party"
    party
    "User"
    user
    "Resource or Artifact"
    resource
  }

`;

export default typeDefs ;
