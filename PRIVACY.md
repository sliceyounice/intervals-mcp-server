# Privacy Policy — Intervals.icu MCP Server

**Service:** https://myintervals.sliceyounice.cc/mcp
**Operator:** Ihor (GitHub: sliceyounice)
**Contact:** sliceyounice@gmail.com
**Last updated:** 24 November 2026

This service is an open-source Model Context Protocol (MCP) server (https://github.com/sliceyounice/intervals-mcp-server, GPL-3.0). It lets you connect your Intervals.icu account to AI assistants such as Claude so the assistant can read and manage your training data on your behalf. It is an independent project and is not affiliated with Intervals.icu.

## 1. What we collect and store

- **Account identifiers:** your Intervals.icu athlete ID.
- **Credentials:** your Intervals.icu API key or OAuth access/refresh tokens. These are stored encrypted at rest (Fernet) in a database on the server and are never written to logs in plain text.
- **Session data:** short-lived tokens issued to your AI assistant (the MCP client) so it can call the service, plus the client registration details needed for the connection to work.
- **Operational logs:** technical logs (timestamps, request paths, error messages) used to keep the service running and diagnose problems.

## 2. Intervals.icu training data

When your AI assistant makes a request, the service retrieves data from Intervals.icu using your credentials and returns it to the assistant. This can include activities, activity streams and intervals, power curves, wellness data, calendar events, and custom items. The service also creates, updates or deletes events and custom items when you ask the assistant to.

This data is relayed in real time. **We do not store, sell, analyse or build profiles from your training data**, and we do not use it for advertising or to train machine-learning models.

## 3. How data is used

Only to (a) authenticate you, (b) make Intervals.icu API calls you or your assistant request, and (c) operate and secure the service.

## 4. Sharing

- **Intervals.icu:** receives the API requests made on your behalf.
- **Your AI assistant provider** (e.g. Anthropic for Claude): receives the data returned for your requests, under your agreement with that provider and their privacy policy.
- **Hosting/infrastructure providers** that run the server.

We do not sell or share your data with anyone else, except if required by law.

## 5. Retention and deletion

Credentials and tokens are kept while your connection is active. You can remove them at any time by:
- disconnecting the connector in your AI assistant,
- revoking the app under Settings in Intervals.icu (or regenerating your API key), or
- emailing sliceyounice@gmail.com to have your stored data deleted. We will act on it within 30 days.

Logs are retained for a limited period (up to 30 days) and then deleted.

## 6. Security

Traffic is encrypted with TLS. Credentials are encrypted at rest, tokens are short-lived, and access to the server is restricted to the operator. No system is perfectly secure, so we cannot guarantee absolute security.

## 7. Your rights

You can ask to access, correct or delete the data we hold about you, or withdraw your consent, by emailing sliceyounice@gmail.com. Depending on where you live (e.g. the EU/UK under GDPR), you may have further rights, including the right to complain to your data protection authority.

## 8. Children

The service is not intended for children under 16.

## 9. Changes

We may update this policy. The current version is always at this address and the "Last updated" date will change.

## 10. Contact

Questions or requests: sliceyounice@gmail.com