# Deciduous Decision Tree Previewer

A VSCode Extension port of [Deciduous](https://www.deciduous.app/) that simplifies building decision trees to model adverse scenarios.

It allows you to document your assumptions about how a system, service, app, etc. will respond to adverse events. Its heritage is in helping defenders anticipate attacker behavior and prepare mitigations accordingly, but it also applies to anticipating reliability-related failures, too.

It is especially useful as a foundation to conduct resilience stress testing / chaos experimentation, allowing you to continually refine your mental models of a system with reality. The end goal of using decision trees is to document your beliefs about how failure will unfold across your system in a given scenario, which can inform design improvements to better sustain resilience to that failure.

Getting started guide for the web version: https://kellyshortridge.com/blog/posts/deciduous-attack-tree-app/

Theme options include:
- `theme: default` - the default tree styling
- `theme: accessible` - for more color differentiation between attack and mitigation nodes
- `theme: classic` - classic Graphviz styling
- `theme: dark` - dark mode

For a more detailed write-up of using decision trees in practice, refer to the book [_Security Chaos Engineering: Sustaining Resilience in Software and Systems._](https://www.securitychaoseng.com/)
