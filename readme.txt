=== AI Bug Hunter ===
Contributors: aibughunter
Tags: debugging, errors, php, analysis, maintenance
Requires at least: 6.3.5
Tested up to: 7.0
Requires PHP: 7.4
Stable tag: 1.0
License: GPLv2 or later
License URI: https://www.gnu.org/licenses/gpl-2.0.html

Analyze WordPress errors with local tools and optional AI. Review or export proposed diffs and follow clear manual repair guidance.

== Description ==

AI Bug Hunter combines error logging, syntax scans, runtime evidence, and comparisons with official WordPress.org sources. When an administrator explicitly opts in, the plugin can contact a selected AI provider to explain an incident, identify patterns, and prepare a proposal for human review.

The WordPress.org edition is an analysis and guidance product. It does not apply executable changes received from an external AI service.

The release was tested across WordPress 6.3.5 through 7.0.2.

The plugin does not block activation or operation based on the installed WordPress version. It also keeps no list of its own about which WordPress releases are affected by a vulnerability. A core-version advisory appears only when a vulnerability feed configured on the server reports one, and the text is informational and names the source it came from.

= WordPress.org edition boundary =

* Analyzes incidents and presents a proposed diff when sufficient evidence exists.
* Exports the proposed diff and diagnostic reports for external review.
* Shows a manual repair guide in a read-only popup whether a reliable diff exists or only a diagnosis is available.
* Registers no AJAX action that applies an AI proposal or sends a report to an external server.
* Does register a revert action, and it is not an exception to the rule above: reverting rewrites bytes from an encrypted backup this plugin created on your own server before a local change. It never writes back anything that came from an AI service.
* Contains no engine that could apply an AI-generated repair. That code was deleted from the package rather than left in place behind a switch, so there is nothing to enable.
* Forces `apply_allowed=false`, `assisted_apply_allowed=false`, and `export_only=true` in AI responses.
* Rejects direct PHP calls that attempt to apply an externally generated executable change.
* Cannot be changed into an applying edition by an option, filter, signature, license, remote policy, or provider response.
* Loads no commercial registration, authorization, pricing, or THOTH API module, and offers no provider that bills through the plugin author.

The administrator must perform any repair based on externally generated material outside this plugin, after reviewing the proposal and testing it on a staging site.

The plugin retains administrator-requested local and deterministic actions that do not originate from an LLM. Examples include comparing a WordPress core file with an official verified source, restoring official core bytes, managing the local early-error witness, or adjusting log permissions. These paths are independent from externally generated repair proposals.

== External services ==

= Optional AI providers =

No AI communication occurs by default. Before testing a connection or requesting AI analysis, an administrator must select a provider and enable the explicit consent setting.

Depending on the incident or scan, the plugin may transmit:

* relevant file excerpts;
* error messages and runtime evidence;
* relative paths and line numbers;
* technical environment metadata needed for diagnosis;
* instructions entered by the administrator.

The purpose is to analyze an incident and generate findings, explanations, or proposals for review. Before transmission, the plugin attempts to redact detectable keys, tokens, email addresses, and IP addresses. Redaction reduces risk but does not guarantee complete anonymity.

These are the only providers this edition can select, save, or connect to. Each one is contacted with the administrator's own account and own API key, and the provider records the usage on that account:

* OpenAI — `api.openai.com` — [Privacy Policy](https://openai.com/policies/privacy-policy/) — [Business Terms](https://openai.com/policies/business-terms/)
* Anthropic — `api.anthropic.com` — [Privacy Policy](https://www.anthropic.com/legal/privacy) — [Commercial Terms](https://www.anthropic.com/legal/commercial-terms)
* Mistral AI — `api.mistral.ai` — [Privacy Policy](https://legal.mistral.ai/terms/privacy-policy) — [Commercial Terms](https://legal.mistral.ai/terms/commercial-terms-of-service)
* An OpenAI-compatible server chosen by the administrator — the operator's privacy policy and terms apply. Public destinations require HTTPS and an additional confirmation.

Consent can be withdrawn by clearing the consent setting and saving. The router checks consent at the single outbound boundary and blocks later requests, including connection tests. Deep AI scans also require confirmation for the specific batch.

= Official WordPress.org services =

When an administrator starts an integrity comparison or official restoration, the plugin may contact `api.wordpress.org`, `downloads.wordpress.org`, `core.svn.wordpress.org`, or the applicable locale download host. The request contains the WordPress version, locale, plugin slug, or relative filename needed to locate official checksums or packages. Private site file contents are not sent. The data is used only to compare or retrieve files published by WordPress.org.

WordPress.org Privacy Policy: https://wordpress.org/about/privacy/

= Optional vulnerability feed =

A server administrator may voluntarily define `ABH_CVE_FEED_URL` in `wp-config.php` to point at an HTTPS vulnerability feed. There is no default feed destination, so this request is never made unless that constant is set. The selected operator's privacy policy and terms apply. The feed receives a standard HTTP GET request and returns declarative vulnerability data that is validated locally before use; it does not receive private site file contents. The request verifies TLS, follows no redirects, refuses unsafe URLs, and caps the size of the response it will read.

= Nothing else is contacted =

The plugin connects to no other external service. It does not send reports to `aibughunter.com`, does not register with a commercial server, and does not call a THOTH API. PayPal, Claude, ChatGPT, and the official project website appear on the Support page only as links that open in the browser when an administrator clicks them; the plugin sends them nothing.

== Installation ==

1. Install and activate the plugin.
2. Local diagnostic features are available without connecting an AI service.
3. To use AI, open AI Bug Hunter > Settings, review the disclosure, select a provider, and give explicit consent.
4. Open Repair help for plain-language next steps. Technical details and a proposed diff appear only when they are available.

== Frequently Asked Questions ==

= Does this edition apply code proposed by an AI? =

No. The WordPress.org edition stops at presenting or exporting a proposed diff and explaining how a qualified administrator can perform the work manually. The code that could have written such a repair to disk is not switched off in this edition, it is not in the package at all.

= What happens when no reliable diff can be generated? =

The plugin keeps the diagnosis and opens a manual guide that identifies the affected file, explains the root cause, lists missing evidence, and provides safe verification steps. It does not invent a patch or repeatedly spend tokens on the same unsupported assumption.

= Does the plugin send data to an AI provider without permission? =

No. Connection tests and AI requests remain blocked until an administrator gives explicit consent.

= Is the entire plugin read-only? =

No. It can perform administrator-requested local and deterministic actions, such as restoring bytes from an official WordPress package. The strict prohibition applies to executable repairs supplied by an external service.

= Is there a commercial edition? =

Yes. It is a separate package with its own slug and distribution channel and is not part of the WordPress.org download.

= Does the Support page transmit anything automatically? =

No. PayPal, Claude, ChatGPT, and the official project website open only after an administrator clicks their links. Bug reports and feature requests remain in the browser until the administrator copies them or opens an editable draft in their own email application.

== Changelog ==

= 1.0 =

* Prepared the first independent WordPress.org release line.
* Made standard English the base language for the readme, interface, generated reports, manual guide, and AI-facing user explanations.
* Converted terminal narration and AI role prompts to English, and added asset cache busting so updated console text loads immediately.
* Tested compatibility from WordPress 6.3.5 through 7.0.2.
* Kept core-version security findings informational; no WordPress release is blocked at activation or runtime.
* Limited externally generated material to analysis, proposed diffs, reports, and manual guidance.
* Added a read-only manual repair popup for diagnosis-only and diff-ready outcomes.
* Reworked Repair help for non-technical users: plain-language meaning and next steps appear first, while developer details remain collapsible.
* Made diff download controls conditional on a real line-by-line change containing additions or removals.
* Reworked Support with PayPal options, separate Pro early-access messaging, a $5 one-off contribution, and recipient-email instructions for provider gifting options.
* Added local, opt-in bug-report and feature-request forms that copy text or open an editable email draft without automatic transmission.
* Added a community giveaway notice that defers entry, eligibility, and timing to published official rules.
* Corrected the WordPress.org readme header to `Tested up to: 7.0` and removed the unnecessary Domain Path header flagged by Plugin Check.
* Removed the standalone Plugins / Plugin Center module, its scan endpoints, and its dedicated assets from the free edition while retaining incident diagnosis for errors originating in plugins.
* Made optional Watchdog installation prominent on the Summary screen instead of hiding it inside scanner details.
* Removed the obsolete included-token allowance and all public "included" or "no charge" messaging; provider usage now refers to the administrator's own provider account.
* Clarified intact-file outcomes: matching the developer's published original does not justify speculative modification and may indicate an earlier runtime state, intentional behavior, or another source.
* Added a guided Mistral setup panel with official key creation, verified model identifiers, endpoint guidance, and an explicit reminder that Mistral controls Free-mode limits.
* Removed stale pre-English translation catalogs so retired Spanish and assisted-repair wording cannot reappear in the public edition.
* Reworded security-rule labels and advisory descriptions to avoid false-positive keyword matches during managed-hosting upload scans without weakening any protection.
* Removed the three legacy files identified by the hosting scanner and replaced their public-edition dependencies with a single read-only preview policy containing no file-mutation implementation.
* Removed assisted-repair, direct-application, root-arming, micro-patch export, and external report-sending actions from the public AJAX surface.
* Added immutable refusals in the edition boundary, engine, and transaction layers.
* Cut commercial registration, authorization, and THOTH API integration out of the public edition: nothing loads those code paths and no setting, filter, or response can reach them.
* Added persistent explicit consent before communication with an AI provider.
* Documented transmitted data, purposes, providers, policies, and official WordPress.org services.
* Fixed a cross-site scripting issue on the plugin's own admin screens. Text that comes from a scanned file or from a server response is now written into the page as text or as an attribute value instead of being pasted into HTML. This includes the two columns of the proposed diff, which were previously inserted without escaping.
* Fixed the privacy redaction so that undoing it can no longer damage a valid AI response. Redacted values are now put back inside the decoded reply and the reply is re-encoded, so a restored file path containing a backslash, or a value containing a line break, no longer turns a successful analysis into a "no valid result" message. Which values get redacted before transmission is unchanged.
* Restored the revert button on the History screen. Reverting rewrites bytes from an encrypted backup this plugin made earlier on your own server, so it stays inside this edition's boundary: it never applies anything produced by an AI service.
* Hardened the optional vulnerability-feed request: it verifies TLS, follows no redirects, refuses unsafe URLs, and limits how much of the response it will read.
* The plugin's private storage folder is now always created inside the WordPress installation. Earlier versions could place it beside the installation folder when that parent directory was writable, which left files outside the area that site backups and host migrations copy. A folder left outside by an earlier version is still used, so existing backups are not orphaned. Activating the plugin no longer creates the folder at all; it is created the first time something actually needs to write to it.
* Removed the built-in table of WordPress releases said to be affected by a vulnerability. The plugin no longer makes that claim on its own authority; a core-version advisory now appears only when a feed configured on the server reports one, and the wording is informational and names its source.
* Stopped removing other plugins' admin notices from the page. On the plugin's own screens such notices are now only collapsed visually, and nothing is deleted from the page anywhere.
* A single failed request now produces a single error message instead of two.
* Cleaning up saved backups now reports what it could not delete instead of always reporting success.
* The early-error witness card now lists each recorded fatal error with its file, line, error type, message, and time, instead of showing only a count.
* Removed unused code from the package: the dormant repair-application engine and its helpers, the micro-patch export routine, and the entry for a provider this edition does not ship. Nothing that was reachable in this edition was removed.
