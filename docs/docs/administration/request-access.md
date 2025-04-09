# Requesting knowledge sharing within Organization segregation

!!! tip "Enterprise edition"

    Platform segregation by organization is available under the "OpenCTI Enterprise Edition" license. Please read the [dedicated page](enterprise.md) to have all the information.

Knowledge that exist in the platform can be shared to one organization but not another: some time existing knowledge is hidden to users because it's restricted to another organization than the user's one. See [organization segregation](organization-segregation.md) to learn about organization sharing.

When users creates knowledge that already exists in the platform but is not visible for any restrictions reasons, a generic error message `Restricted entity already exists` is displayed.

Platform administrator can configure a request access workflow to allows users to request access to a knowledge that already exists but is not visible because of organization restriction. This workflow will create a specific Request For Information.

## Configuration to allows users to request access to restricted knowledge

### Configuration of the Request For Information settings

Open the configuration of request for information entity.

![Request for Information entity settings](assets/request-access/entity-setting-rfi.png)

Configure the "Specific workflow for request access:

![Example of request access workflow disabled](assets/request-access/specific-workflow.png)

1. Configure all status that can be used for request access use case. Note that the `Request for Information` will be created with the first status in this list.

2. Configure the status that will be used when the request is accepted

3. Configure the status that will be used when the request is declined

4. Configure the group that will be allowed to see the `Request for Information` created automatically by the platform.


![Example of request access workflow configured](assets/request-access/specific-workflow-configured.png)

## Requesting an access

Once the configuration is complete, user that attempt to create an existing knowledge will have a new button "Request Access" proposed.

![Example of error with button](assets/request-access/restricted-entity.png)

Then users will be able to give more detail on reason that lead to this request, select one of their organization and request access.

![Example of request access form](assets/request-access/request-access-popup.png)

### Accepting or declining a request to access to knowledge

Users who are both:

- in the organization where the knowledge actually belong
- in the group that has been configured in Request for information entity settings

Will receive a dedicated Request for information for example:

![Example of dedicated Request for information](assets/request-access/rfi-dedicated.png)

> Note that this specific Request for Information is automatically under [authorized member restricted access](authorized-members.md) for confidentiality reason.

The knowledge that is requested to be shared, can be found in related entities.
There is two dedicated button "Validate" and "Decline": with one click on Validate, the knowledge will be shared as requested.

User that are allowed to see the dedicated Request for Information and allowed to share the knowledge, will also be notified on dedicated Request for Information creation.
![Exemple of notification](assets/request-access/request-access-notifications.png)

## Disabling request access feature

If you have attempted to use the functionality but need to remove it due to policy:

- In entity setting, delete all status in "Specific Workflow for Request Access" section. 
- You can alternatively remove the group in `Validator membership`. 

This will restore the default behavior, and the button will not appear in the error message `Restricted entity already exists`.

![Example of request access workflow disabled](assets/request-access/specific-workflow.png)