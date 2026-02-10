# Contributing to HARDN

Thank you for your interest in contributing to HARDN.

HARDN exists to make Linux systems more secure, more understandable, and more resilient, without turning security into an exclusive or opaque discipline. Whether you are fixing a typo, improving a hardening rule, writing documentation, reviewing logic, or contributing code, your time and effort are appreciated.

This document explains how to contribute in a way that keeps the project healthy, respectful, and useful for everyone.

## Our Philosophy

HARDN is built on a few simple principles.

Security should be practical, not performative.  
Hardening should be transparent, not magical.  
Contributions should be thoughtful, not rushed.  
Collaboration should be respectful, not hierarchical.

You do not need to be a security expert to contribute. Curiosity, care, and a willingness to learn are valued here.

## Ways to Contribute

There are many ways to help HARDN grow.

### Code Contributions

You can contribute to core hardening logic, detection and validation improvements, performance or reliability enhancements, and bug fixes. Code contributions should prioritize clarity, correctness, and security reasoning over cleverness.

### Documentation

Documentation is just as important as code. Contributions may include clarifying existing documentation, adding usage examples, improving explanations for new users, or correcting inaccuracies and outdated references.

### Security Research

Security-focused contributions are welcome. This includes reviewing hardening rules against real-world threats, suggesting improvements based on benchmarks, STIGs, or best practices, and identifying edge cases or false positives.

### Testing and Feedback

Testing HARDN on different systems, reporting bugs or unexpected behavior, and suggesting usability improvements are all valuable contributions.

## Before You Start

Before contributing, please take a moment to read the README, review existing issues and pull requests, and search for open discussions related to your idea. This helps avoid duplicate work and keeps conversations focused.

## Contribution Workflow

Fork the repository and create a new branch with a descriptive name such as feature/add-kernel-check, fix/systemd-permissions, or docs/clarify-installation.

Make your changes with care. Keep changes focused, avoid unrelated refactors, and follow the existing project structure and style.

If your change affects behavior, test it locally and document what you tested and how. Security-related changes should be especially well reasoned.

Write clear and honest commit messages that explain what changed and why. Avoid vague messages.

Open a pull request that explains what changed, why it changed, any tradeoffs or limitations, and how it was tested. If the pull request is still a work in progress, mark it clearly.

## Code Expectations

Prefer clarity over cleverness.  
Avoid unnecessary dependencies.  
Be explicit with security logic.  
Comment why something exists, not just what it does.  
Assume future readers may not be security experts.

If something is security-sensitive, state that plainly.

## Security Considerations

If you discover a security vulnerability in HARDN itself, do not open a public issue. Follow the reporting instructions in SECURITY.md. Responsible disclosure protects users and contributors alike.

## Reviews and Feedback

All contributions are reviewed with care. Feedback is meant to improve quality, reduce risk, and share context. Reviews are never personal. If something is unclear, ask. If you disagree, explain your reasoning respectfully.

## Community Standards

All contributors are expected to treat others with respect, communicate professionally, assume good intent, and be patient with learners. Harassment, hostility, or dismissive behavior is not tolerated.

## Attribution

Contributors are credited through Git history, release notes when applicable, and project documentation. Your work matters and will be acknowledged.

## Final Note from us, The Unix Dudes

HARDN is not just a tool. It is a shared effort to make systems safer without fear, confusion, or gatekeeping.

If you care about security, transparency, and building tools that genuinely help people, you are welcome here.

Thank you for contributing.
