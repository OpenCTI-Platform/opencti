---
id: version-1.0.2-reports-create
title: Create reports
sidebar_label: Create reports
original_id: reports-create
---

## Introduction

If you want to add a report or a source which is not already in the platform to analyze it, you have two possibilities:

* either the report is in a database for which a connector to OpenCTI exists. You just have to find your report in this database and follow the procedure to import it (for instance, in MISP, you have to tag it, as well as in Zotero). After that, you just have to wait for the report to be imported (it depends on the time of execution set for the connector).

* or you can create the report from scratch directly in OpenCTI. For that, go in the "Reports" service and click on the orange bottom right  button. Once you have filled in the information, hit the "Create" button (don't worry for the URL of your source, it comes at the next step).

The created report will appear at the top of the "all reports" table with a "new" tag. If you click on it, the dashboard of the source will display. 

![Created report](assets/usage/report_created.png "Created report")

## Add external references

You can then add information that you had not previously typped in. For instance, if you want to add an URL to a report to point to its source, you can click on the small "plus" sign at the right of the "external references" box, and in the windows which just appeared, click again on the orange bottom right button to create a brand new source.

![Report external references](assets/usage/report_external-references.png "Report external references")

> Note that the bottom boxes on the page, which are displaying graphs and charts, cannot be directly modified, but will update automatically if you add observables, entities or knowledge to the report.