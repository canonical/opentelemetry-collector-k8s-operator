mock_provider "juju" {}

variables {
  channel            = "dev/edge"
  model_uuid         = "00000000-0000-0000-0000-000000000000"
  storage_directives = { data = "1G" }
}

# The charm exposes a dedicated `istio-ingress` endpoint for the
# `istio_ingress_route` interface. `ingress` is Traefik's `traefik_route`, so a
# consumer cannot substitute one for the other.
run "istio_ingress_is_distinct_from_traefik_ingress" {
  command = plan

  assert {
    condition     = output.requires.istio_ingress == "istio-ingress"
    error_message = "Expected requires.istio_ingress to be \"istio-ingress\", got ${output.requires.istio_ingress}"
  }

  assert {
    condition     = output.requires.ingress == "ingress"
    error_message = "Expected requires.ingress to stay Traefik's \"ingress\", got ${output.requires.ingress}"
  }
}
