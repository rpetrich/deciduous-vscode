// The module 'vscode' contains the VS Code extensibility API
// Import the module and reference it with the alias vscode in your code below
import * as vscode from 'vscode';
import { convertToDot, type Input } from './layout';
import * as jsyaml from 'js-yaml';
const { Graphviz } = require('@hpcc-js/wasm-graphviz');

const sampleGraph = `title: (Example) Attack Tree for S3 Bucket with Video Recordings

facts:
- wayback: API cache (e.g. Wayback Machine)
  from:
  - reality: '#yolosec'
- public_bucket: S3 bucket set to public
  from:
  - bucket_search: '#yolosec'
- subsystem_with_access: Subsystem with access to bucket data
  from:
  - compromise_user_creds

attacks:
- bucket_search: AWS public buckets search
  from:
  - disallow_crawling
- brute_force:
  from:
  - private_bucket
- phishing:
  from:
  - private_bucket
  - internal_only_bucket:
    backwards: true
  - access_control_server_side:
    backwards: true
- compromise_user_creds: Compromise user credentials
  from:
  - brute_force
  - phishing
- analyze_web_client: Manually analyze web client for access control misconfig
  from:
  - lock_down_acls
- compromise_admin_creds: Compromise admin creds
  from:
  - phishing
- compromise_aws_creds: Compromise AWS admin creds
  from:
  - phishing
- intercept_2fa: Intercept 2FA
  from:
  - 2fa
- ssh_to_public_machine: SSH to an accessible machine
  from:
  - compromise_admin_creds: '#yolosec'
  - compromise_aws_creds:
  - intercept_2fa
- lateral_movement_to_machine_with_access: Lateral movement to machine with access to target bucket
  from:
  - ip_allowlist_for_ssh
- compromise_presigned: Compromise presigned URLs
  from:
  - phishing
- compromise_quickly: Compromise URL within N time period
  from:
  - short_lived_presigning
- recon_on_s3: Recon on S3 buckets
  from:
  - private_bucket
  - disallow_bucket_urls:
    backwards: true
  - 2fa:
    backwards: true
- find_systems_with_access: Find systems with R/W access to target bucket
  from:
  - recon_on_s3: '#yolosec'
- exploit_known_vulns: Exploit known 3rd party library vulns
  from:
  - find_systems_with_access
- buy_0day:
  from:
  - vuln_scanning
- discover_0day: Manual discovery of 0day
  from:
  - vuln_scanning
- exploit_vulns: Exploit vulns
  from:
  - buy_0day
  - discover_0day
- aws_0day: 0day in AWS multitenant systems
  from:
  - ips
- supply_chain_backdoor: Supply chain compromise (backdoor)
  from:
  - single_tenant_hsm

mitigations:
- disallow_crawling: Disallow crawling on site maps
  from:
  - reality
- private_bucket: Auth required / ACLs (private bucket)
  from:
  - reality
- lock_down_acls: Lock down web client with creds / ACLs
  from:
  - subsystem_with_access
- access_control_server_side: Perform all access control server side
  from:
  - analyze_web_client
- 2fa: 2FA
  from:
  - compromise_admin_creds: '#yolosec'
  - compromise_aws_creds
- ip_allowlist_for_ssh: IP allowlist for SSH
  from:
  - ssh_to_public_machine
- short_lived_presigning: Make URL short lived
  from:
  - compromise_presigned
- disallow_bucket_urls: Disallow the use of URLs to access buckets
  from:
  - compromise_quickly
- vuln_scanning: 3rd party library checking / vuln scanning
  from:
  - exploit_known_vulns
- ips: Exploit prevention / detection
  from:
  - exploit_vulns
- single_tenant_hsm: Use single tenant AWS HSM
  from:
  - aws_0day:
    implemented: false
- internal_only_bucket: No public system has R/W access (internal only)
  from:
  - find_systems_with_access

goals:
- s3_asset: Access video recordings in S3 bucket (attackers win)
  from:
  - wayback: '#yolosec'
  - public_bucket
  - subsystem_with_access
  - analyze_web_client
  - lateral_movement_to_machine_with_access
  - compromise_presigned
  - compromise_quickly
  - exploit_vulns
  - aws_0day
  - supply_chain_backdoor
- company_bank_account: Access company bank account
  from:
  - intercept_2fa

# filter can be used to show only paths that flow through specific nodes
filter:
- s3_asset`;

const webViewHTML = `<!doctype html>
<html>
<head>
	<script>
		const vscode = acquireVsCodeApi();
		window.addEventListener("message", ({ data }) => {
			document.body.innerHTML = data.html;
			const svgElement = document.body.querySelector("svg");
			if (svgElement) {
				const scale = 0.75;
				svgElement.setAttribute("width", parseInt(svgElement.getAttribute("width"), 10) * scale + "pt");
				svgElement.setAttribute("height", parseInt(svgElement.getAttribute("height"), 10) * scale + "pt");
			};
			// Add quick linky links
			for (const title of document.body.querySelectorAll("title")) {
				title.parentNode.style.cursor = "pointer";
				title.parentNode.addEventListener("click", () => {
					const node = title.textContent;
					const matches = node.match(/^(\\w+)->(\\w+)$/);
					if (matches) {
						vscode.postMessage({ event: "select-edge", from: matches[1], to: matches[2] });
					} else {
						vscode.postMessage({ event: "select-node", id: node });
					}
				});
				// Clone edge paths and make them thicker to make them easier to click
				if (title.parentNode.getAttribute("class") === "edge") {
					const path = title.parentNode.querySelector("path");
					if (path) {
						const thickPath = path.cloneNode(true);
						thickPath.setAttribute("stroke", "transparent");
						thickPath.setAttribute("stroke-width", "15px");
						title.parentNode.insertBefore(thickPath, path);
					}
				}
			}
		});
		window.addEventListener("load", () => {
			vscode.postMessage({ event: "load" });
		});
	</script>
	<style>
		svg {
			display: inline-block;
			position: absolute;
			top: 0;
			left: 0;
		}
		svg > g:first-child > polygon:first-child {
			display: none !important;
		}
	</style>
</head>
<body>
</body>
</html>`;

let currentSVG = "";

export function activate(context: vscode.ExtensionContext) {

	let activePanel: vscode.WebviewPanel | undefined;

	async function loadWebViewPanel(panel: vscode.WebviewPanel) {
		let loadedResolve = () => {};
		const loaded = new Promise<void>(resolve => {
			loadedResolve = resolve;
		});

		let editor: vscode.TextEditor | undefined;
		const messageDisposable = panel.webview.onDidReceiveMessage(async message => {
			switch (message.event) {
				case "load":
					loadedResolve();
					break;
				case "select-edge":
					if (editor !== undefined) {
						const text = editor.document.getText();
						const firstSearch = `\n- ${message.to}`;
						const firstIndex = text.indexOf(firstSearch);
						if (firstIndex !== -1) {
							const secondSearch = `- ${message.from}`;
							const secondIndex = text.indexOf(secondSearch, firstIndex + firstSearch.length);
							if (secondIndex !== -1) {
								await vscode.window.showTextDocument(editor.document, {
									selection: new vscode.Selection(
										editor.document.positionAt(secondIndex + 2),
										editor.document.positionAt(secondIndex + secondSearch.length),
									),
									viewColumn: editor.viewColumn,
								});
							}
						}
					}
					break;
				case "select-node":
					if (editor !== undefined) {
						const text = editor.document.getText();
						const search = `\n- ${message.id}`;
						const index = text.indexOf(search);
						if (index !== -1) {
							await vscode.window.showTextDocument(editor.document, {
								selection: new vscode.Selection(
									editor.document.positionAt(index + 3),
									editor.document.positionAt(index + search.length),
								),
								viewColumn: editor.viewColumn,
							});
						}
					}
					break;
				}
		});
		panel.webview.html = webViewHTML;

		const textChangeDisposable = vscode.workspace.onDidChangeTextDocument((e: vscode.TextDocumentChangeEvent) => {
			if (e.document === vscode.window.activeTextEditor?.document) {
				rerender();
			}
		});

		const graphviz = await Graphviz.load();
		await loadedResolve();

		const editorChangeDisposable = vscode.window.onDidChangeActiveTextEditor(rerender);
		const panelDisposable = panel.onDidDispose(() => {
			if (activePanel === panel) {
				activePanel = undefined;
			}
			textChangeDisposable.dispose();
			editorChangeDisposable.dispose();
			messageDisposable.dispose();
			panelDisposable.dispose();
		});
		rerender();

		function rerender() {
			const newEditor = vscode.window.activeTextEditor;
			if (newEditor !== undefined) {
				editor = newEditor;
				try {
					const parsed = jsyaml.load(editor.document.getText());
					const { dot, types, title } = convertToDot(parsed as Input);
					if (title || Object.keys(types).length !== 0) {
						currentSVG = graphviz.layout(dot, "svg", "dot");
					}
				} catch (e) {
					currentSVG = "";
				}
				panel.webview.postMessage({ html: currentSVG });
			}
		}
	}

	async function openSampleDocument() {
		const editor = vscode.window.activeTextEditor;
		if (editor !== undefined && editor.document.uri.scheme === "untitled" && editor.document.getText() === "") {
			await editor.edit(editBuilder => {
				editBuilder.insert(new vscode.Position(1, 1), sampleGraph);
			});
			await vscode.languages.setTextDocumentLanguage(editor.document, "yaml");
		} else {
			const document = await vscode.workspace.openTextDocument({
				language: "yaml",
				content: sampleGraph,
			});
			await vscode.window.showTextDocument(document, {
				viewColumn: editor?.viewColumn
			});
		}
	}

	const commandDisposable = vscode.commands.registerCommand('deciduous-previewer.showPreview', async () => {
		if (activePanel !== undefined) {
			activePanel.dispose();
			activePanel = undefined;
		} else {
			activePanel = vscode.window.createWebviewPanel(
				'deciduous-previewer.preview',
				'Deciduous Preview',
				{ viewColumn: vscode.ViewColumn.Two, preserveFocus: true },
				{ retainContextWhenHidden: true, enableScripts: true },
			);
			await loadWebViewPanel(activePanel);
			if (currentSVG === "") {
				await openSampleDocument();
			}
		}
	});

	const exportSVGDisposable = vscode.commands.registerCommand('deciduous-previewer.exportSVG', async () => {
		if (currentSVG !== "") {
			const uri = await vscode.window.showSaveDialog({
				filters: { "SVG Image": ["svg"] },
			});
			if (uri !== undefined) {
				const bytes = new TextEncoder().encode(currentSVG);
				await vscode.workspace.fs.writeFile(uri, bytes);
				await vscode.workspace.openTextDocument(uri);
			}
		} else {
			await vscode.window.showErrorMessage("No active Deciduous document");
		}
	});

	const serializableDisposable = vscode.window.registerWebviewPanelSerializer('deciduous-previewer.preview', {
		async deserializeWebviewPanel(webviewPanel) {
			if (activePanel !== undefined) {
				activePanel.dispose();
			}
			activePanel = webviewPanel;
			await loadWebViewPanel(webviewPanel);
		},
	});

	context.subscriptions.push(commandDisposable);
	context.subscriptions.push(exportSVGDisposable);
	context.subscriptions.push(serializableDisposable);
}

export function deactivate() {}
