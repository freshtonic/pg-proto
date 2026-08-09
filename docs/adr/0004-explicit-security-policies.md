# Require explicit security policies in component builders

Client-role and server-role builders require explicit TLS and authentication
policies before they can build a component. They provide no permissive security
defaults: plaintext transport, disabled certificate verification, and trust
authentication remain available only through explicit, searchable policy values.
This deliberately trades setup convenience for protection against accidental
deployment with a weaker security posture.
