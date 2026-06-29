mock_provider "juju" {}

variables {
  channel    = "dev/edge"
  model_uuid = "00000000-0000-0000-0000-000000000000"
}

run "warns_when_storage_directives_unset" {
  command = plan

  expect_failures = [check.storage_directives]
}

run "no_warning_when_storage_directives_set" {
  command = plan

  variables { storage_directives = { "data" = "1G" } }
}
