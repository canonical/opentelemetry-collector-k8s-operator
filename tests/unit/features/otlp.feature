Feature: Forward rules to an application
    As a Juju admin
    I want to have all enabled rules
    sent to an application for alerting

    Background:
        Given the operator is initialized
        * juju topology of an otelcol unit
        * "forward_alert_rules" config is set to True

    Scenario: The provider offers an HTTP OTLP endpoint for metrics
        Given a receive-otlp relation with a requirer offering no rules
        When integrated with our charm
        * the operator executes the "update_status" event
        Then the provider offers an HTTP OTLP endpoint for metrics

    Scenario: The requirer filters out unsupported protocols and telemetries
        Given a send-otlp relation with a provider offering an HTTP OTLP endpoint for logs and metrics
        When integrated with our charm
        Given a send-otlp relation with a provider offering two OTLP endpoints: gRPC for traces and HTTP for metrics
        When integrated with our charm
        * the operator executes the "update_status" event and returns a charm
        Then the requirer chooses two OTLP endpoints: HTTP for metrics and HTTP for logs and metrics

    Scenario: Related to A (send-otlp) and B (receive-otlp)
        Given a send-otlp relation with a provider offering no OTLP endpoints
        * the remote app is named: "a"
        When integrated with our charm
        Given a receive-otlp relation with a requirer offering no rules
        * the remote app is named: "b"
        When integrated with our charm
        * the operator executes the "update_status" event and returns a charm
        Then the data transfer is cyclic: "no"

    Scenario: Related to A (receive-otlp) and B (send-otlp)
        Given a send-otlp relation with a provider offering no OTLP endpoints
        * the remote app is named: "b"
        When integrated with our charm
        Given a receive-otlp relation with a requirer offering no rules
        * the remote app is named: "a"
        When integrated with our charm
        * the operator executes the "update_status" event and returns a charm
        Then the data transfer is cyclic: "no"

    Scenario: Related to A over both send and receive OTLP
        Given a send-otlp relation with a provider offering no OTLP endpoints
        * the remote app is named: "a"
        When integrated with our charm
        Given a receive-otlp relation with a requirer offering no rules
        * the remote app is named: "a"
        When integrated with our charm
        * the operator executes the "update_status" event and returns a charm
        Then the data transfer is cyclic: "yes"

    Scenario: Related to A over send-otlp and B over both send and receive OTLP
        Given a send-otlp relation with a provider offering no OTLP endpoints
        * the remote app is named: "a"
        * the remote app has id: 123
        When integrated with our charm
        Given a send-otlp relation with a provider offering no OTLP endpoints
        * the remote app is named: "b"
        * the remote app has id: 456
        When integrated with our charm
        Given a receive-otlp relation with a requirer offering no rules
        * the remote app is named: "b"
        When integrated with our charm
        * the operator executes the "update_status" event and returns a charm
        Then the data transfer is cyclic: "yes"

    Scenario: Bundled rules are not forwarded to the provider
        Given "forward_alert_rules" config is set to False
        * a receive-otlp relation with a requirer offering no rules
        When integrated with our charm
        Given a send-otlp relation with a provider offering no OTLP endpoints
        When integrated with our charm
        Given a send-otlp relation with a provider offering no OTLP endpoints
        When integrated with our charm
        * the charm config is applied
        * the operator executes the "update_status" event
        Then the bundled rules are sent to the provider

    Scenario: Bundled rules are forwarded to the provider
        Given "forward_alert_rules" config is set to True
        * a receive-otlp relation with a requirer offering no rules
        When integrated with our charm
        Given a send-otlp relation with a provider offering no OTLP endpoints
        When integrated with our charm
        Given a send-otlp relation with a provider offering no OTLP endpoints
        When integrated with our charm
        * the charm config is applied
        * the operator executes the "update_status" event
        Then the bundled rules are sent to the provider

    Scenario: Otelcol adds its own topology metadata to the databag
        Given "forward_alert_rules" config is set to True
        * a receive-otlp relation with a requirer offering no rules
        When integrated with our charm
        Given a send-otlp relation with a provider offering no OTLP endpoints
        When integrated with our charm
        Given a send-otlp relation with a provider offering no OTLP endpoints
        When integrated with our charm
        * the charm config is applied
        * the operator executes the "update_status" event
        Then otelcol adds its own topology metadata to the databag
