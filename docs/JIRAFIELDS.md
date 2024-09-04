## JIRA custom fields support

JIRA Custom fields can be polupated via mappings, using definitions in application.yaml file or passing the appropriate command-line arguments.
Each field mapping accepts the following attributes:

|Attribute|Mandatory|Description|
|---|---|---|
|type|X|The CxONE field type to get data from (see [CxOne fields for mappings](FIELDSMAPPINGS.md) for details)|
|name|X|The CxONE field name to get data from (see [CxOne fields for mappings ](FIELDSMAPPINGS.md) for details)|
|jira-field-type|X|The JIRA field type. The value must comply to the JIRA type defs. See below the supported types|
|jira-field-name|X|The target issue field name (field labels can also be used to identify the field)|
|jira-default-value||A default value to use in case CxONE does not deliver a value|
|skip-update||The JIRA field shall be populated only on ticketing creation, skipping updates (True/False)|
|offset||Integer value for date offset in days, used only for *system-date* (default is 0)|

## Supported JIRA field types

Supported JIRA field types are:
- text
- component
- label
- single-select
- radio
- multi-select
- cascading-select
- single-version-picker
- multi-version-picker
- security

## Using application.yaml file

Adding a fields sub-section, inside jira section, and define there the list of the desired mappings.
Example:
```
jira:
  ...
  fields:
    - type: cx
      name: cx-scan
      jira-field-name: Scan Tags
      jira-field-type: text
    - type: result
      name: comment
      jira-field-name: Risk Comment
      jira-field-type: text
      skip-update: true
    - type: result
      name: category
      jira-field-name: Risk Name
      jira-field-type: text
```

## Using command-line arguments

Passing one argument for each mapping attribute, indicating also the field mapping number.
Example:
```
cxoneflow --app x --scanid y ... --jira.fields.0.type cx   \
    --jira.fields.0.name cx-scan   \
    --jira.fields.0.jira-field-name "Scan Tags"   \
    --jira.fields.0.jira-field-type text   \
    --jira.fields.1.type result   \
    --jira.fields.1.name comment   \
    --jira.fields.1.jira-field-name "Risk Comment"   \
    --jira.fields.1.jira-field-type text   \
    --jira.fields.1.skip-update true   \
    --jira.fields.2.type result   \
    --jira.fields.2.name category   \
    --jira.fields.2.jira-field-name "Risk Name"   \
    --jira.fields.2.jira-field-type text
```
