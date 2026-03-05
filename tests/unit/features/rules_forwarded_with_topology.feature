Feature: Forward rules to an application
    As a Juju admin
    I want to have all enabled rules
    sent to an application for alerting

    Background:
        Given the operator is initialized
        * a logql alerting rule
        * a promql alerting rule
        * empty remote appdata
        * "forward_alert_rules" config is set to True

    Scenario: Rules from related charms are intentionally not forwarded
        Given "forward_alert_rules" config is set to False
        * a "send-otlp" endpoint
        When integrated with our charm
        Given a "receive-otlp" endpoint
        * logql and promql alerting rules in remote appdata
        When integrated with our charm
        * the charm is config is applied
        * the operator executes the "update_status" event
        Then local appdata contains the following rules:
            | format | upstream_rules | generic_rules | bundled_rules |
            | logql  | 0              | 0             | 0             |
            | promql | 0              | 1             | 3             |

    Scenario: Aggregate bundled and generic rules
        Given a "send-otlp" endpoint
        When integrated with our charm
        Given a "receive-otlp" endpoint
        When integrated with our charm
        * the operator executes the "update_status" event
        Then bundled promql, alerting rules are published to local appdata, with topology
        * generic promql, alerting rules are published to local appdata, with topology
        Then local appdata contains the following rules:
            | format | upstream_rules | generic_rules | bundled_rules |
            | logql  | 0              | 0             | 0             |
            | promql | 0              | 1             | 3             |

    Scenario: Aggregate remote rules
        Given a "send-otlp" endpoint
        When integrated with our charm
        Given a "receive-otlp" endpoint
        * logql and promql alerting rules in remote appdata
        When integrated with our charm
        * the operator executes the "update_status" event
        Then bundled promql, alerting rules are published to local appdata, with topology
        * generic promql, alerting rules are published to local appdata, with topology
        * upstream logql, alerting rules are published to local appdata, with topology
        * upstream promql, alerting rules are published to local appdata, with topology
        Then local appdata contains the following rules:
            | format | upstream_rules | generic_rules | bundled_rules |
            | logql  | 1              | 0             | 0             |
            | promql | 1              | 1             | 3             |

    Scenario: Publish all aggregated remote rules to multiple relations
        Given a "send-otlp" endpoint
        When integrated with our charm
        Given a "send-otlp" endpoint
        When integrated with our charm
        Given a "receive-otlp" endpoint
        * logql and promql alerting rules in remote appdata
        When integrated with our charm
        * the operator executes the "update_status" event
        Then bundled promql, alerting rules are published to local appdata, with topology
        * generic promql, alerting rules are published to local appdata, with topology
        * upstream logql, alerting rules are published to local appdata, with topology
        * upstream promql, alerting rules are published to local appdata, with topology
        Then local appdata contains the following rules:
            | format | upstream_rules | generic_rules | bundled_rules |
            | logql  | 1              | 0             | 0             |
            | promql | 1              | 1             | 3             |

    Scenario: Compressed alert rules are readable
        Given a "send-otlp" endpoint
        When integrated with our charm
        Given a "receive-otlp" endpoint
        * logql and promql alerting rules in remote appdata
        When integrated with our charm
        * the operator executes the "update_status" event
        Then local appdata alert rules are compressed
