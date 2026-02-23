# Architecture

## Purpose

security-event-tracker evaluates risk signals, policy violations, and suspicious activity for faster incident response.

## Components

- Signal intake layer
- Assessment engine
- Output formatter for downstream automation

## Runtime Flow

1. Receive signal text/event.
2. Compute deterministic risk score.
3. Emit structured assessment result.
