---
name: translation
description: Ensure application are well translated, and that the translations are up-to-date.
---

# Translation

## Instructions
In opencti-front application, all texts are translated using t_i18n hook.
Its really important to translate all texts to provide a good user experience.
Base language is english. All translations must be located in en.json file in the lang folder.
To be sure that all texts are translated, the command `yarn verify-translation` must be executed.
If some texts are not translated, analyze the result of the command and add the missing translations in en.json.
For text coming from opencti-graphql, the translations are located in lang/back.
For text coming from opencti-front, the translations are located in lang/front.
When en.json has no longer missing translations, all new translations MUST be added in ALL the other languages supported.
Supported languages available are: de (german) fr (french), es (spanish), it (italian), ja (japonese), ko (korean), ru (russian), zh (chinese) 
Translate the texts in the correct language for each file using the best translation possible, with respect of the alphabetical order.
Remember that OpenCTI is a threat intelligence platform to adapt and find the best translations.
If you find close semantics representing the same meaning, that you can consider as duplicates, adapt the text and the translation to prevent too many entries.

## Examples
A new test is added in any front files, like t_i18n('This field is an example')
"This field is an example" must be added in en.json file in the lang front folder.
"This field is an example":"This field is an example"
Then all languages must be translated.