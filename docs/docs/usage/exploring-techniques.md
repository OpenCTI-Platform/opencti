# Techniques

When you click on "Techniques" in the left-side bar, you access all the "Techniques" tabs, visible on the top bar on the left. By default, the user directly access the "Attack pattern" tab, but can navigate to the other tabs as well.

From the `Techniques` section, users can access the following tabs:
- `Attack pattern`: attacks pattern used by the threat actors to perform their attacks. By default, OpenCTI is provisionned with attack patterns from MITRE ATT&CK matrices (for CTI) and DISARM matrix (for FIMI).
- `Narratives`: In OpenCTI, narratives used by threat actors can be represented and linked to other Objects. Narratives are mainly used in the context of disinformation campaigns where it is important to trace which narratives have been and are still used by threat actors.
- `Courses of action`: A Course of Action is an action taken either to prevent an attack or to respond to an attack that is in progress. It may describe technical, automatable responses (applying patches, reconfiguring firewalls) but can also describe higher level actions like employee training or policy changes. For example, a course of action to mitigate a vulnerability could describe applying the patch that fixes it.
- `Data sources`: Data sources represent the various subjects/topics of information that can be collected by sensors/logs. Data sources also include data components, 
- `Data components`: Data components identify specific properties/values of a data source relevant to detecting a given ATT&CK technique or sub-technique.

## Attack pattern

### General presentation

Attacks pattern used by the threat actors to perform their attacks. By default, OpenCTI is provisionned with attack patterns from MITRE ATT&CK matrices and CAPEC (for CTI) and DISARM matrix (for FIMI).

In the MITRE STIX 2.1 documentation, an `Attack pattern` is defined as such :

> Attack Patterns are a type of TTP that describe ways that adversaries attempt to compromise targets. Attack Patterns are used to help categorize attacks, generalize specific attacks to the patterns that they follow, and provide detailed information about how attacks are performed. An example of an attack pattern is "spear phishing": a common type of attack where an attacker sends a carefully crafted e-mail message to a party with the intent of getting them to click a link or open an attachment to deliver malware. Attack Patterns can also be more specific; spear phishing as practiced by a particular threat actor (e.g., they might generally say that the target won a contest) can also be an Attack Pattern.

When clicking on the Attack pattern tab at the top left, you access the list of all the attack pattern you have access too, in respect with your [allowed marking definitions](../administration/users.md). You can then search and filter on some common and specific attributes of attack patterns.

### Visualizing Knowledge associated with an Attack pattern

When clicking on an Attack pattern, you land on its Overview tab. For an Attack pattern, the following tabs are accessible:

- Overview: Overview of Attack pattern is a bit different as the usual described [here](overview.md). The "Details" box is more structured and contains information about:
   - parent or subtechniques (as in the MITRE ATT&CK matrices), 
   - related kill chain phases
   - Platform on which the Attack pattern is usable,
   - permission required to apply it
   - Related detection technique
   - Courses of action to mitigate the Attack pattern
   - Data components in which find data to detect the usage of the Attack pattern
- Knowledge: a complex tab that regroups all the structured Knowledge linked to the Attack pattern. Different thematic views are proposed to easily see Threat Actors and Intrusion Sets using this techniques, linked incidents, etc.
- Analyses: as described [here](overview.md).
- Data: as described [here](overview.md).
- History: as described [here](overview.md).

## Narratives

### General presentation

In OpenCTI, narratives used by threat actors can be represented and linked to other Objects. Narratives are mainly used in the context of disinformation campaigns where it is important to trace which narratives have been and are still used by threat actors.

An example of Narrative can be "The country A is weak and corrupted" or "The ongoing operation aims to free people". 

Narrative can be a mean in the context of a more broad attack or the goal of the operation, a vision to impose.

When clicking on the Narrative tab at the top left, you access the list of all the Narratives you have access too, in respect with your [allowed marking definitions](../administration/users.md). You can then search and filter on some common and specific attributes of narratives.

### Visualizing Knowledge associated with a Narrative

When clicking on a Narrative, you land on its Overview tab. For a Narrative, the following tabs are accessible:

- Overview: as described [here](overview.md).
- Knowledge: a complex tab that regroups all the structured Knowledge linked to the Narratives. Different thematic views are proposed to easily see the Threat actors and Intrusion Set using the Narrative, etc. 
- Analyses: as described [here](overview.md).
- Data: as described [here](overview.md).
- History: as described [here](overview.md).

## Courses of action

### General presentation

In the MITRE STIX 2.1 documentation, an `Course of action` is defined as such :

> A Course of Action is an action taken either to prevent an attack or to respond to an attack that is in progress. It may describe technical, automatable responses (applying patches, reconfiguring firewalls) but can also describe higher level actions like employee training or policy changes. For example, a course of action to mitigate a vulnerability could describe applying the patch that fixes it.

When clicking on the `Courses of action` tab at the top left, you access the list of all the Courses of action you have access too, in respect with your [allowed marking definitions](../administration/users.md). You can then search and filter on some common and specific attributes of course of action.

### Visualizing Knowledge associated with a Course of action

When clicking on a `Course of Action`, you land on its Overview tab. For a Course of action, the following tabs are accessible:

- Overview: Overview of Course of action is a bit different as the usual described [here](overview.md). In "Details" box, mitigated attack pattern are listed.
- Knowledge: a complex tab that regroups all the structured Knowledge linked to the Narratives. Different thematic views are proposed to easily see the Threat actors and Intrusion Set using the Narrative, etc. 
- Analyses: as described [here](overview.md).
- Data: as described [here](overview.md).
- History: as described [here](overview.md).

## Data sources & Data components

### General presentation

In the MITRE ATT&CK documentation, `Data sources` are defined as such :

> Data sources represent the various subjects/topics of information that can be collected by sensors/logs. Data sources also include data components, which identify specific properties/values of a data source relevant to detecting a given ATT&CK technique or sub-technique.

### Visualizing Knowledge associated with a Data source or a Data components

When clicking on a `Data source` or a `Data component`, you land on its Overview tab. For a Course of action, the following tabs are accessible:

- Overview: as described [here](overview.md).
- Data: as described [here](overview.md).
- History: as described [here](overview.md).