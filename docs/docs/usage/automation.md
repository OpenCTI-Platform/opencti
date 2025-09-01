# Playbooks Automation

!!! tip "Enterprise edition"

    Playbooks automation is available under the "OpenCTI Enterprise Edition" license. Please read the [dedicated page](../administration/enterprise.md) to have all information.


OpenCTI playbooks are flexible automation scenarios which can be fully customized and enabled by platform administrators to enrich, filter and modify the data created or updated in the platform. 

Playbook automation is accessible in the user interface under Data > Processing > Automation.

!!! note "Right needed"

    You need the "Manage credentials" [capability](../administration/users.md) to use the Playbooks automation, because you will be able to manipulate data simple users cannot access.

You will then be able to:

- add labels depending on enrichment results to be used in threat intelligence-driven detection feeds,
- create reports and cases based on various criteria,
- trigger enrichments or webhooks in given conditions,
- modify attributes such as first_seen and last_seen based on other pieces of knowledge,
- etc.

## Playbook philosophy

Consider Playbook as a STIX 2.1 bundle pipeline. 

Initiating with a component listening to a data stream, each subsequent component in the playbook processes a received STIX bundle. These components have the ability to modify the bundle and subsequently transmit the altered result to connected components.

In this paradigm, components can send out the STIX 2.1 bundle to multiple components, enabling the development of multiple branches within your playbook.

A well-designed playbook end with a component executing an action based on the processed information. For instance, this may involve writing the STIX 2.1 bundle in a data stream.

!!! note "Validate ingestion"

    The STIX bundle processed by the playbook won't be written in the platform without specifying it using the appropriate component, i.e. "Send for ingestion".

## Create a playbook
### Manual creation 

It is possible to create as many playbooks as needed, which run independently. You can give a name and description to each playbook.

![Create a new playbook](assets/playbook_create.png)

The first step to define in the playbook is your event source.
To do so, click on the grey rectangle in the center of the workspace and select the input component that suits your needs.

![Choose input component](assets/playbook_input.png)

### Duplicate a playbook 

It is possible to duplicate a playbook, to easily replicate a playbook. You can do it directly by cliking on the burger menu (the 3 dots) at the end of the row and click on duplicate, or directly when you're inside a playbook.


### Import/Export a playbook
#### Export a playbook

If you need to share a playbook with a colleague that is not on the same platform than you (or if you need to troubleshoot a playbook issue), you can now export your playbook directly: by cliking on the burger menu (the 3 dots) at the end of the row and click on duplicate, or directly when you're inside a playbook.


#### Import a playbook

You can import a playbook in OpenCTI coming either from your own platform or another platform. Simply go to playbooks, click on import & select the playbook you want to import.

!!! warning "Verify your playbook"

    Imported playbooks may contain data that does not exist in your platform. For instance, the initial playbook could have listened on a specific label & applied a specific marking that does not exist in your platform. Therefore, when you import a playbook, always check all the boxes/steps to ensure your playbook will run smoothly.

**Applicable steps & data to verify:**
- Listen knowledge events/ Manual enrollment / Query knowledge on regular basis / Match knowledge / Reduce knowledge / Manipulate knowledge
   - Verify if any of the following data is correctly defined in your playbook, otherwise create it in your platform
      - Taxonomies: any not existing taxonomy will be shown as deleted (Labels, vocabularies...) 
      - Specific instances (entity/observable): If your playbook was listening on a specific instance, verify that the instance exists in your platform
      - Marking: verify that the marking you're listening to exists in your platform
      - Author: verify that the identities in your platform exist
      - Creators: verify that you have existing users in your platform
- Enrich through connector
   - Verify if any of the following data is correctly define in your playbook, otherwise create it in your platform
      - Connector exists in your platform   
- Container wrapper
   - Verify if any of the following data is correctly define in your playbook, otherwise create it in your platform
      - Task template exists in your platform.
- Send to notifier
   - Verify that the notifier exists in your platform
   - Verify that the target exsits in your platform

### Listen knowledge events
With this event source, the playbook will be triggered on any knowledge event (create, update or delete) that matches the selected filters.
Note that you are limited to a subset of filters available for stream events that contain STIX data objects.

![Listening creation event for TLP:GREEN IPs and domain names](assets/playbook_listen.png)

### Query knowledge on a regular basis

With such event source, the playbook will query knowledge on a hourly / daily / weekly / monthly basis, according to filters you might have set.

If you check the option "Only last modified entities after the last run', then the playbook will exclude from each run the entities that have not changed since last run. 

![Querying last incidents](assets/playbook_query_regular.png)

### Available for manual enrollment / trigger

Use this event source for setting up a playbook that will be triggered manually on specific entities.
You can configure filters in the component so that this playbook will be suggested for certain entities during the manual enrollment.
For more details about manual enrollment, see dedicated section below.

![Manual enroll important incidents](assets/playbook_manual_source.png)

## Design your workflow

Then you have flexible choices for the next steps to:

- filter the initial knowledge,
- enrich data using external sources and internal rules,
- modify entities and relationships by applying patches,
- write the data, send notifications, 
- etc.

... using the various playbook components at your disposal.

By clicking the burger button of a component, you can replace it by another one.

By clicking on the arrow icon in the bottom right corner of a component, you can develop a new branch at the same level.

By clicking the "+" button on a link between components, you can insert a component between the two.

Do not forget to start your Playbook when ready, with the Start option of the burger button placed near the name of your Playbook.

## Components of playbooks

![List of current components](assets/playbook_components.png)

#### Log data in standard output

Will write the received STIX 2.1 bundle in platform logs with configurable log level and then send out the STIX 2.1 bundle unmodified.

#### Send for ingestion

Will pass the STIX 2.1 bundle to be written in the data stream. This component has no output and should end a branch of your playbook.

#### Filter Knowledge

Will allow you to define filter and apply it to the received STIX 2.1 bundle. The component has 2 output, one for data matching the filter and one for the remainder.

By default, filtering is applied to entities having triggered the playbook. You can toggle the corresponding option to apply it to all elements in the bundle (elements that might result from enrichment for example).

#### Enrich through connector

Will send the received STIX 2.1 bundle to the stated enrichment connector and send out the modified bundle.
Entities that are passed to this stage must be compatible with the enrichment connector being used, as otherwise the playbook may stop at this stage. The *Reduce Knowledge* component can be used to filter out incompatible entities from being passed to this stage.

#### Manipulate knowledge

Will add, replace or remove compatible attribute of the entities contains in the received STIX 2.1 bundle and send out the modified bundle.

By default, modification is applied to entities having triggered the playbook. You can toggle the corresponding option to apply it to all elements in the bundle (elements that might result from enrichment for example).

#### Container wrapper

Will modify the received STIX 2.1 bundle to include the entities into an container of the type you configured. 
By default, wrapping is applied to entities having triggered the playbook. You can toggle the corresponding option to apply it to all elements in the bundle (elements that might result from enrichment for example).

#### Share with organizations

Will share every entity in the received STIX 2.1 bundle with Organizations you configured. Your platform needs to have declared a platform main organization in Settings/Parameters.

#### Apply predefined rule

Will apply a complex automation built-in rule. This kind of rule might impact performance. Current rules are:

- First/Last seen computing extension from report publication date: will populate first seen and last seen date of entities contained in the report based on its publication date,
- Resolve indicators based on observables (add in bundle): will retrieve all indicators linked to the bundle's observables from the database,
- Resolve observables an indicator is based on (add in bundle): retrieve all observables linked to the bundle's indicator from the database,
- Resolve container references (add in bundle): will add to the bundle all the relationships and entities the container contains (if the entity having triggered the playbook is not a container, the output of this component will be empty),
- Resolve neighbors relations and entities (add in bundle): will add to the bundle all relations of the entity having triggered the playbook, as well as all entities at the end of these relations, i.e. the "first neighbors" (if the entity is a container, the output of this component will be empty).


#### Send to notifier

Will generate a Notification each time a STIX 2.1 bundle is received.

#### Promote observable to indicator

Will generate indicator based on observables contained in the received STIX 2.1 bundle. 

By default, it is applied to entities having triggered the playbook. You can toggle the corresponding option to apply it to all observables in the bundle (e.g. observables that might result from predefined rule).

You can also add all indicators and relationships generated by this component in the entity having triggered the playbook, if this entity is a container.

#### Extract observables from indicator  

Will extract observables based on indicators contained in the received STIX 2.1 bundle. 

By default, it is applied to entities having triggered the playbook. You can toggle the corresponding option to apply it to all indicators in the bundle (e.g. indicators that might result from enrichment.

You can also add all observables and relationships generated by this component in the entity having triggered the playbook, if this entity is a container.

#### Reduce Knowledge

Will filter out any entities in the current stage that do not match the filter conditions in the stage. If the original triggering entity is a container, such as a report or case, then the container itself cannot be filtered out, and will be passed to subsequent stages.

## Enroll manually an entity into a playbook

You can enroll individual entities in playbooks by using the action "Enroll in playbook" from the entity details view.

![Enroll entity in playbook](assets/playbook_enroll_entity.png)

This will open a drawer where you can choose the playbook you want to trigger on this entity.

![Enroll entity in playbook](assets/playbook_enroll_select.png)

In this list, you will find:

* active playbooks that have set an "Available for manual enrollment / trigger" event source
* active playbooks with "Listen knowledge events" event source which filters match the entity

## Monitor playbook activity

At the top right of the interface, you can access execution trace of your playbook and consult the raw data after every step of your playbook execution.

![Steps monitoring](assets/playbook_traces.png)




