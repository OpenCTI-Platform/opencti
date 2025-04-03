# Ask AI

!!! tip "Enterprise edition"

    Ask AI is available under the "OpenCTI Enterprise Edition" license.

    [Please read the dedicated page to have all information](../administration/enterprise.md)
    

## Prerequisites for using Ask AI

There are several possibilities for Enterprise Edition customers to use OpenCTI AI endpoints:

- Use the Filigran AI Service leveraging our custom AI model using the token given by the support team.
- Use OpenAI, MistralAI or AzureAI cloud endpoints using your own tokens.
- Deploy or use local AI endpoints (Filigran can provide you with the custom model).

[Please read the configuration documentation](../deployment/configuration.md)

!!! info "Beta Feature"
    
    Ask AI is a beta feature as we are currently fine-tuning our models. Consider checking important information.

## How it works

Even if in the future, we would like to leverage AI to do [RAG](https://blogs.nvidia.com/blog/what-is-retrieval-augmented-generation/), for the moment we are mostly using AI to analyze and produce texts or images, based on data directly sent into the prompt.

This means that if you are using Filigran AI endpoint or a local one, your data is never used to re-train or adapt the model and everything relies on a pre-trained and fixed model. When using the `Ask AI` button in the platform, a prompt is generated with the proper instruction to generate the expected result and use it in the context of the button (in forms, rich text editor etc.).

### Filigran custom model

We are hosting a scalable AI endpoint for all SaaS or On-Prem enterprise edition customers, this endpoint is based on MistralAI with a model that will be adapted over time to be more effective when processing threat intelligence related contents.

The model, which is still in beta version, will be adapted in the upcoming months to reach maturity at the end of 2024. It can be shared with on-prem enterprise edition customers under NDA.

## Functionalities of Ask AI

Ask AI is represented by a dedicated icon wherever on of its functionalities is available to use.

![Create a new playbook](assets/askai_icon.png)

### Assistance for writing meaningful content 

Ask AI can assist you for writing better textual content, for example better title, name, description and detailed content of Objects.

- Fix spelling & grammar: try to improve the text from a formulation and grammar perspective.  
- Make it shorter/longer: try to shorten or lengthen the text.
- Change tone: try to change the tone of the text. You can select if you want the text to be written for Strategic (Management, decision makers), Tactical (for team leaders) or Operational (for technical CTI analysts) audiences.
- Summarize: try to summarize the text in bullet points.
- Explain: try to explain the context of the subject's text based on what is available to the LLM.

### Assistance for importing data from documents

Fom the Content tab of a Container (Reports, Groupings and Cases), Ask AI can also assist you for importing data contained in uploaded documents into OpenCTI for further exploitation.

- Generate report document: Generate a text report based on the knowledge graph (entities and relationships) of this container.
- Summarize associated files: Generate a summary of the selected files (or all files associated to this container).
- Try to convert the selected files (or all files associated to this container) in a STIX 2.1 bundle you will then be able to use at your convenience (for example importing it into the platform).

![Generating report with Ask AI](assets/askai_generatereport.png)

![Example of a generated content](assets/askai_generatedcontent.png)

A short video on the FiligranHQ YouTube channel presents tha capabilities of AskAI: https://www.youtube.com/watch?v=lsP3VVsk5ds.

### Assistance for finding specific entities (Natural Language Query)

An Ask AI button is available in the top search bar. It enables to switch the search bar in NLQ mode where you can write questions or assertions in natural language.
![Ask AI button in the top search bar](assets/nlq-button.png)

The system uses a Large Language Model (LLM) to generate corresonding filters based on your question. The model constructs filters in the OpenCTI filters format with empty ``filterGroups``. Thus, filters are currently limited to one level of imbrication: a list of filters separated by a single and/or mode.
The LLM constructs the filters with :
- existing filter keys (attributes, relations input names and some special filter keys),
- the available operators (equals, greater than, etc.),
- existing entity and relationship types for the possible values of entity types filters.

The NLQ filters result is then used to display the list of matching entities.
![Example of results with NLQ](assets/nlq-example.png)

If the question is not understood or out of the OpenCTI cyber context, no filters may be found.
![Example of results with NLQ with no result](assets/nlq-no-result.png)


!!! warning "Token usage and cost notice"

    The Natural Language Query feature relies on heavy prompts sent to the language model to describe the filters structure and provide examples. These complex queries may generate significant token usage.
    When using a custom API endpoint (e.g., OpenAI, Mistral, AzureAI) with your own API key, this may result in increased costs. We recommend checking your provider's pricing documentation to estimate costs accurately.    
    For our SaaS customers, queries are routed through our hosted model instance and do not incur additional costs.

#### NLQ results involving an entity

If your question includes a term detected as a term representing an entity, a search will be triggered across multiple fields (name, value, aliases, etc.) to resolve it.
- If a match is found, its ID will be used in the generated filters.
  ![Example of results with NLQ and a found entity](assets/nlq-result-found-entity.png)

- If no match is found, the part of the filters involving the entity will be skipped.
  ![Example of results with NLQ and a not found entity](assets/nlq-result-not-found-entity.png)

#### Actual NLQ model limitations

This is the first version of an NLQ model. It is still in development and may not yet handle all use cases.

In particular, here are some limitations:

- It is not possible to search among relationships (only entities).

  Example: ``List the relationships involving Paradise Ransomware.``

- The model is not built to handle dates yet.

  Example: ``List the reports published after January.``

- The model cannot filter on properties of related entities (second level information).

  Example: ``List the indicators related to a malwares located in Europe.``

- No Multi-level logic combinations yet, queries requiring embedded filters combinations (e.g., mixing AND/OR modes between different filters) are not yet supported.
  
  Example: ``What are the malwares created by admin or having label 'test'?`` 


## Improving generated elements of Ask AI

Be aware that the text quality is highly dependent on the capabilities of the associated LLM.

That is why every generated text by Ask AI is provided in a dedicated panel, allowing you to verify and rectify any error the LLM could have made.
