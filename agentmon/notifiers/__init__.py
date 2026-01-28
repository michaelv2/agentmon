"""Notifiers package for sending alerts to external services."""

from agentmon.notifiers.slack import SlackConfig, SlackNotifier

__all__ = ["SlackConfig", "SlackNotifier"]
