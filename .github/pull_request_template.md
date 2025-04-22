## Issue
<!-- What issue is this PR trying to solve? -->


## Solution
<!-- A summary of the solution addressing the above issue -->


## Context
<!-- What is some specialized knowledge relevant to this project/technology -->


## Testing Instructions
<!-- What steps need to be taken to test this PR? -->


## Upgrade Notes
<!-- To upgrade from an older revision of the charm, ... -->


## Checklist
<!-- Common tasks related to charm modifications, ... -->
- Are you adding an exporter or receiver to the config?
  - [ ] If exporter (or a receiver which makes client-like requests to a server, i.e. prometheus scraping), did you add a `"tls": {"insecure_skip_verify": ...}` section to its config?
