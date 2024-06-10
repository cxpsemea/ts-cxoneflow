# Checkmarx One Flow for Feedback

Tickets feeder for CxOne (CxFlow)

### Objective

Add ability to manage feedback from scans originated in CXONE.
Mimics the legacy CxFlow features regarding ticket management (opening, closing, and reopening tickets).
Usable as command-line tool and, therefore, in CI/CD automations.

## Coverage

The tool can manage JIRA tickets from CXONE scans.
Currently only JIRA is supported.

## Configuration

The tool uses a configuration "application.yaml" file with the equivalent structure to the one existing in the legacy CxFlow.
The main objective is to facilitate transition, for those how have been using CxFlow and are now migrating to CxONE.
By default, the configuration file is located at the application root folder. However, another configuration file can be used, via command line argument "--config-file".
All the configuration options can be set in the yaml file, in environment variables (prefixed with CXTOOL_), or via command line arguments.
A simple log file is created in a subfolder named "logs", unless other location is indicated via the command-line argument "--logs-folder".

## Operation

This tool **CANNOT** be used to start scans. 
For complete automation, use the CxONE CLI to conduct scans, obtain from there the ScanId, and then pass it to this tool to process the tickets.
The folder "examples" contain CI/CD pipelines illustrating the usage.
Currently, can process results from SAST, SCA, and IaC scanners.

## JIRA

The tickets created in JIRA maintain the same structure and the same identifiers as the created by the legacy CxFlow.
With this approach, existing SAST or SCA tickets, created by CxFlow, will not be duplicated by this tool.
JIRA cloud and server, v9.x and up, are supported.
