---
id: inferences
title: Inferred relations
sidebar_label: Inferred relations
---

## Introduction

OpenCTI is based on an [entities-relations model](../usage/model) that allows users to connect many entities together. In some cases, it could be interesting that some facts to be automatically inferred from others. For instance, if a `campaign` targeted the sector of `electricity`, which is a sub-sector of the `energy` sector, and is attributed to an `intrusion set`, the analyst wants to know that this specific `intrusion set` has targeted the `energy` sector.

In OpenCTI, this can be represented by:

![Relations](assets/reference/relations.png "Relations")

To derive the implicit facts of this kind of knowledge, OpenCTI relies on the [inferences capability of the Grakn database](https://dev.grakn.ai/docs/schema/rules). The result is explained directly in the application when displaying an inferred relation:

![Inference 1](assets/reference/inference1.png "Inference 1")

## Implemented rules of inferences

The implemented rules are expressed here in pseudo-code.

### Usage rules

<pre><code>when {
	A attributed-to B
	A uses C
}, then {
	B uses C
}
</code></pre>

### Target rules

<pre><code>when {
	A attributed-to B
	A targets C
}, then {
	B targets C
}
</code></pre>

<pre><code>when {
	A targets B
	A uses C
}, then {
	C targets A
}
</code></pre>

<pre><code>when {
	A part-of (gathering) B
	C targets A
}, then {
	C targets B
}
</code></pre>

<pre><code>when {
	A localized-in (localization) B
	C targets A
}, then {
	C targets B
}
</code></pre>

### Attribution rules

<pre><code>when {
	A attributed-to B
	B attributed-to C
}, then {
	A attributed-to C
}
</code></pre>

### Localization rules

<pre><code>when {
	A localized-in (localization) B
	B localized-in (localization) C
}, then {
	A localized-in (localization) C
}
</code></pre>