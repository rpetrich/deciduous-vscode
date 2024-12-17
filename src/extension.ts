// The module 'vscode' contains the VS Code extensibility API
// Import the module and reference it with the alias vscode in your code below
import * as vscode from 'vscode';
import { convertToDot, embedDotComment, embedSvgComment, trailingPngComment, type Input } from './layout';
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
		async function performCommand(command, data) {
			switch (command) {
				case "update":
					document.body.innerHTML = data;
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
					break;
				case "exportPNG":
					// create the SVG URL
					const svgFile = new File([data.svg], "graph.svg", {
						"type": "image/svg+xml",
					});
					const svgURL = URL.createObjectURL(svgFile);
					// load the SVG image
					const image = document.createElement("img");
					await new Promise((resolve, reject) => {
						image.onload = resolve;
						image.onerror = reject;
						image.src = svgURL;
					});
					// draw the SVG image onto a canvas
					const canvas = document.createElement("canvas");
					const scale = 2;
					canvas.width = image.width * scale;
					canvas.height = image.height * scale;
					canvas.style.display = "none";
					document.body.appendChild(canvas);
					const context = canvas.getContext("2d");
					context.drawImage(image, 0, 0, image.width * scale, image.height * scale);
					// convert the canvas image to a PNG
					const blob = await new Promise(resolve => canvas.toBlob(resolve, { type: "image/png" }));
					// revoke the SVG URL
					URL.revokeObjectURL(svgURL);
					// destroy the temporary canvas
					document.body.removeChild(canvas);
					// convert the PNG blob to an array buffer
					return new Blob([blob, data.trailer], { type: "image/png" }).arrayBuffer();
			}
		}
		window.addEventListener("message", async ({ data: { data, command, id } }) => {
			let value;
			try {
				value = await performCommand(command, data);
			} catch (e) {
				vscode.postMessage({ event: "reject", id, value: e.toString() });
				return;
			}
			vscode.postMessage({ event: "resolve", id, value });
		});
		window.addEventListener("load", () => {
			vscode.postMessage({ event: "resolve", id: 0 });
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

export function activate(context: vscode.ExtensionContext) {

	let activePanel: vscode.WebviewPanel | undefined;
	let sendCommand: ((name: string, data: any) => Promise<any>) | undefined;

	let currentInput = "";
	let currentDot = "";
	let currentSVG = "";
	let editor: vscode.TextEditor | undefined;

	async function loadWebViewPanel(panel: vscode.WebviewPanel) {
		const remotePromises = [] as { resolve: (value: any) => void, reject: (error: any) => void}[];
		function pushRemotePromise() {
			return {
				id: remotePromises.length,
				promise: new Promise((resolve, reject) => {
					remotePromises.push({ resolve, reject });
				}),
			};
		}
		function popRemotePromise(id: number) {
			const result = remotePromises[id];
			delete remotePromises[id];
			return result;
		}
		async function performRemoteCommand(name: string, data: any) {
			const { id, promise } = pushRemotePromise();
			if (!await panel.webview.postMessage({ command: name, id, data })) {
				throw new Error("web view is not live");
			}
			return promise;
		}

		const messageDisposable = panel.webview.onDidReceiveMessage(async message => {
			switch (message.event) {
				case "resolve":
					popRemotePromise(message.id as number).resolve(message.value);
					break;
				case "reject":
					popRemotePromise(message.id as number).reject(new Error(message.value));
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
		const { promise: loaded } = pushRemotePromise();
		panel.webview.html = webViewHTML;

		const textChangeDisposable = vscode.workspace.onDidChangeTextDocument(async (e: vscode.TextDocumentChangeEvent) => {
			if (e.document === vscode.window.activeTextEditor?.document) {
				await rerender();
			}
		});

		const graphviz = await Graphviz.load();
		loaded.then(rerender);

		const editorChangeDisposable = vscode.window.onDidChangeActiveTextEditor(rerender);
		const panelDisposable = panel.onDidDispose(() => {
			if (activePanel === panel) {
				activePanel = undefined;
				sendCommand = undefined;
			}
			textChangeDisposable.dispose();
			editorChangeDisposable.dispose();
			messageDisposable.dispose();
			panelDisposable.dispose();
		});

		sendCommand = performRemoteCommand;

		function rerender() {
			const newEditor = vscode.window.activeTextEditor;
			if (newEditor !== undefined) {
				editor = newEditor;
				try {
					currentInput = editor.document.getText();
					const parsed = jsyaml.load(currentInput);
					const { dot, types, title } = convertToDot(parsed as Input);
					currentDot = dot;
					if (title || Object.keys(types).length !== 0) {
						currentSVG = graphviz.layout(dot, "svg", "dot");
					}
				} catch (e) {
					currentSVG = "";
				}
				return performRemoteCommand("update", currentSVG);
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

	const commandDisposable = vscode.commands.registerCommand('deciduous-vs.showPreview', async () => {
		if (activePanel !== undefined) {
			activePanel.dispose();
			activePanel = undefined;
		} else {
			activePanel = vscode.window.createWebviewPanel(
				'deciduous-vs.preview',
				'Deciduous',
				{ viewColumn: vscode.ViewColumn.Two, preserveFocus: true },
				{ retainContextWhenHidden: true, enableScripts: true },
			);
			await loadWebViewPanel(activePanel);
			if (currentSVG === "") {
				await openSampleDocument();
			}
		}
	});

	const exportSVGDisposable = vscode.commands.registerCommand('deciduous-vs.export', async () => {
		if (currentSVG !== "") {
			let defaultUri;
			if (editor !== undefined && editor.document.uri.scheme !== "untitled") {
				defaultUri = editor.document.uri.with({
					path: editor.document.uri.path.replace(/(\.\w+)?$/, ".png"),
				});
			}
			const uri = await vscode.window.showSaveDialog({
				defaultUri,
				filters: {
					"PNG Image": ["png"],
					"SVG Image": ["svg"],
					"Graphviz DOT": ["dot"],
				},
			});
			if (uri !== undefined) {
				if (/\.png$/i.test(uri.path)) {
					const buffer = await sendCommand!("exportPNG", { svg: currentSVG, trailer: trailingPngComment(currentInput)});
					await vscode.workspace.fs.writeFile(uri, new Uint8Array(buffer));
				} else if (/\.dot$/i.test(uri.path)) {
					const bytes = new TextEncoder().encode(embedDotComment(currentDot, currentInput));
					await vscode.workspace.fs.writeFile(uri, bytes);
				} else {
					const bytes = new TextEncoder().encode(embedSvgComment(currentSVG, currentInput));
					await vscode.workspace.fs.writeFile(uri, bytes);
				}
			}
		} else {
			await vscode.window.showErrorMessage("No active Deciduous document");
		}
	});

	const serializableDisposable = vscode.window.registerWebviewPanelSerializer('deciduous-vs.preview', {
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
