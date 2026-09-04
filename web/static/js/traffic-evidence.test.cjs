const fs = require('node:fs');
const test = require('node:test');
const assert = require('node:assert/strict');

const html = fs.readFileSync('web/templates/index.html', 'utf8');
const script = fs.readFileSync('web/static/js/traffic-evidence.js', 'utf8');
const vulnerabilityScript = fs.readFileSync('web/static/js/vulnerability.js', 'utf8');
const transformScript = fs.readFileSync('web/static/js/traffic-transforms.js', 'utf8');
const replayScript = fs.readFileSync('web/static/js/traffic-replay.js', 'utf8');
const router = fs.readFileSync('web/static/js/router.js', 'utf8');
const styles = fs.readFileSync('web/static/css/style.css', 'utf8');
const zh = JSON.parse(fs.readFileSync('web/static/i18n/zh-CN.json', 'utf8'));
const en = JSON.parse(fs.readFileSync('web/static/i18n/en-US.json', 'utf8'));

test('流量证据列表不再展示常驻的不可信内容提示', () => {
    assert.doesNotMatch(html, /traffic-evidence-notice/);
    assert.doesNotMatch(html, /目标内容不可信/);
    assert.match(html, /style\.css\?v=20260904-1/);
    assert.match(html, /router\.js\?v=20260827-2/);
    assert.match(html, /traffic-evidence\.js\?v=6/);
});

test('漏洞详情以紧凑按钮在当前页弹窗显示多个完整数据包', () => {
    assert.match(vulnerabilityScript, /class="vulnerability-traffic-evidence-trigger"/);
    assert.match(vulnerabilityScript, /label\.textContent = '查看完整数据包'/);
    assert.match(vulnerabilityScript, /const vulnerabilityTrafficEvidenceItems = new Map\(\)/);
    assert.match(vulnerabilityScript, /openVulnerabilityPacketModal\(vulnId\)/);
    assert.match(vulnerabilityScript, /\/api\/traffic-transactions\/\$\{encodeURIComponent\(transactionId\)\}/);
    assert.match(vulnerabilityScript, /items\.forEach\(\(item, index\) =>/);
    assert.doesNotMatch(vulnerabilityScript, /switchPage\('traffic-evidence'\)/);
    assert.match(html, /id="vulnerability-packet-modal"[^>]+aria-modal="true"/);
    assert.match(html, /id="vulnerability-packet-transactions"/);
    assert.match(html, /id="vulnerability-packet-stages"/);
    assert.match(styles, /\.vulnerability-traffic-evidence\s*\{[\s\S]*?width: fit-content/);
    assert.match(styles, /\.vulnerability-packet-body\s*\{[\s\S]*?grid-template-columns:/);
    assert.match(styles, /\.vulnerability-packet-stages\s*\{[\s\S]*?grid-template-columns: repeat\(2/);
    assert.match(html, /vulnerability\.js\?v=19/);
});

test('压缩响应默认显示解压正文，二进制回退为 Hex 而不是 Base64', () => {
    assert.match(script, /正文已按 Content-Encoding 解压/);
    assert.match(script, /二进制正文 · Hex/);
    assert.match(script, /body_view/);
    assert.doesNotMatch(script, /\[base64 encoded body\]/);
    assert.match(vulnerabilityScript, /正文已按 Content-Encoding 解压/);
    assert.match(vulnerabilityScript, /二进制正文 · Hex/);
    assert.doesNotMatch(vulnerabilityScript, /\[base64 encoded body\]/);
});

test('漏洞数据包弹窗可分别快捷复制每个请求或响应报文', () => {
    assert.doesNotMatch(html, /id="vulnerability-packet-copy"/);
    assert.doesNotMatch(vulnerabilityScript, /vulnerabilityPacketCopyText/);
    assert.match(vulnerabilityScript, /vulnerability-packet-message-copy/);
    assert.match(vulnerabilityScript, /writeVulnerabilityPacketClipboard\(rawPacket\)/);
    assert.match(vulnerabilityScript, /navigator\.clipboard\.writeText\(text\)/);
    assert.match(vulnerabilityScript, /document\.execCommand\('copy'\)/);
    assert.match(vulnerabilityScript, /copyButton\.textContent = copied \? '已复制' : '复制失败'/);
    assert.match(styles, /\.vulnerability-packet-message-copy\.is-copied/);
});

test('仅不完整正文在对应报文卡片底部显示截断状态', () => {
    assert.match(script, /if \(!complete\) \{/);
    assert.match(script, /create\('div', 'traffic-evidence-packet-truncation'\)/);
    assert.match(script, /truncation\.setAttribute\('role', 'status'\)/);
    assert.match(script, /当前显示 \$\{storedBytes\}\/\$\{totalBytes\} bytes/);
    assert.doesNotMatch(script, /traffic-evidence-packet-note/);
});

test('列表、详情和报文正文拥有明确且互不冲突的纵向滚动容器', () => {
    assert.match(styles, /\.traffic-evidence-content\s*\{[\s\S]*?grid-template-rows: auto minmax\(0, 1fr\);[\s\S]*?height: 100%;[\s\S]*?overflow: hidden;/);
    assert.match(styles, /\.traffic-evidence-table-wrap\s*\{[\s\S]*?flex: 1 1 0;[\s\S]*?min-height: 0;[\s\S]*?overflow: auto;/);
    assert.match(styles, /\.traffic-evidence-detail-dialog\s*\{[\s\S]*?flex-direction: column;[\s\S]*?overflow: hidden;/);
    assert.match(styles, /\.traffic-evidence-detail-stages\s*\{[\s\S]*?min-height: 0;[\s\S]*?overflow-y: auto;[\s\S]*?overscroll-behavior: contain;/);
    assert.match(styles, /\.traffic-evidence-packet pre\s*\{[\s\S]*?overflow: auto;[\s\S]*?scrollbar-gutter: stable both-edges;/);
});

test('流量请求可取消且超过十五秒会显示明确错误', () => {
    assert.match(script, /const REQUEST_TIMEOUT_MS = 15000/);
    assert.match(script, /new root\.AbortController\(\)/);
    assert.match(script, /root\.apiFetch\(url, \{ signal: controller\.signal \}\)/);
    assert.match(script, /请求超过 15 秒，请检查网络后重试/);
    assert.match(script, /listRequestID/);
    assert.match(script, /detailRequestID/);
});

test('每条流量证据直接标记本机或容器执行位置', () => {
    assert.match(html, /<th>脚本<\/th><th>运行位置<\/th><th>执行来源<\/th>/);
    assert.match(script, /if \(mode === 'container'\) return '容器'/);
    assert.match(script, /if \(mode === 'host'\) return '本机'/);
    assert.match(script, /traffic-evidence-runtime-badge is-\$\{runtimeMode\}/);
    assert.match(styles, /\.traffic-evidence-runtime-badge\.is-container/);
    assert.match(styles, /\.traffic-evidence-runtime-badge\.is-host/);
});

test('经过 Traffic Transform 的流量在列表、详情与解码阶段醒目标记', () => {
    assert.match(script, /traffic-evidence-transform-badge/);
    assert.match(script, /脚本已解码/);
    assert.match(script, /traffic-evidence-transform-summary/);
    assert.match(script, /is-transform-output/);
    assert.match(styles, /\.traffic-evidence-transform-badge/);
    assert.match(styles, /\.traffic-evidence-transform-summary/);
	assert.match(script, /重发包 · 脚本/);
});

test('侧栏以流量为父菜单并提供证据、重发包和加密解密三个独立路由', () => {
    assert.match(html, /data-page="traffic"[\s\S]*?toggleSubmenu\('traffic'\)[\s\S]*?data-page="traffic-evidence"[\s\S]*?data-page="traffic-replay"[\s\S]*?data-page="traffic-transforms"/);
    assert.match(html, /id="page-traffic-replay"[^>]+data-require-permission="traffic:replay"/);
    assert.match(html, /id="page-traffic-transforms"[^>]+data-require-permission="traffic_transform:read"/);
    assert.match(router, /pageId === 'traffic-evidence' \|\| pageId === 'traffic-replay' \|\| pageId === 'traffic-transforms'/);
    assert.ok((router.match(/'traffic-replay'/g) || []).length >= 3);
    assert.ok((router.match(/'traffic-transforms'/g) || []).length >= 3);
    for (const locale of [zh, en]) {
        assert.equal(typeof locale.nav.traffic, 'string');
        assert.equal(typeof locale.nav.trafficEvidence, 'string');
        assert.equal(typeof locale.nav.trafficReplay, 'string');
        assert.equal(typeof locale.nav.trafficTransforms, 'string');
    }
});

test('加密解密页面展示脚本、Runner 和注入对话并在脚本内管理作用范围', () => {
    for (const title of ['脚本', 'Runner', '注入的对话']) {
        assert.match(html, new RegExp(title));
    }
    assert.doesNotMatch(html, /id="traffic-transform-tab-cases"|id="traffic-transform-panel-cases"/);
    assert.doesNotMatch(html, /traffic-transform-overview|traffic-transform-workflow|traffic-transform-boundary/);
    assert.match(html, /traffic-transforms\.js\?v=10/);
    assert.match(router, /case 'traffic-transforms':[\s\S]*?initTrafficTransformsPage\(\)/);
    assert.match(transformScript, /apiFetch\('\/api\/traffic-transforms'/);
    assert.match(transformScript, /function renderScopeRows\(container, transformID\)/);
    assert.match(transformScript, /function renderRunner\(\)/);
    assert.match(transformScript, /脚本已删除/);
    assert.match(transformScript, /function renderSourceCode\(source\)/);
    assert.match(transformScript, /function openEditor\(item\)/);
    assert.match(transformScript, /function deleteScript\(item\)/);
    assert.match(transformScript, /确认删除脚本/);
    assert.match(transformScript, /confirmDeleteTransformID/);
    assert.doesNotMatch(transformScript, /root\.confirm/);
    assert.match(transformScript, /method: 'PUT'/);
    assert.match(transformScript, /method: 'DELETE'/);
    assert.match(html, /id="traffic-transform-editor"[^>]+aria-modal="true"/);
    assert.match(transformScript, /traffic-transform-revisions\/\$\{encodeURIComponent\(revisionID\)\}\/source/);
    assert.match(styles, /\.traffic-transform-workspace\s*\{/);
    assert.match(styles, /\.traffic-transform-script-detail\s*\{/);
    assert.match(styles, /\.traffic-transform-scope-table/);
    assert.match(styles, /\.traffic-transform-source-dialog\s*\{/);
});

test('重发包从证据事务载入请求并按原事务接口提交修改', () => {
    assert.match(html, /id="traffic-evidence-send-replay"/);
    assert.match(html, /traffic-replay\.js\?v=5/);
    assert.match(router, /case 'traffic-replay':[\s\S]*?initTrafficReplayPage\(\)/);
    assert.match(replayScript, /client_request/);
    assert.match(replayScript, /traffic-transactions\/\$\{encodeURIComponent\(state\.transactionID\)\}\/replay/);
    assert.match(replayScript, /原执行位置重发/);
	assert.match(replayScript, /解密 Hook 已旁路执行/);
	assert.match(replayScript, /完成解密、修改与重编码/);
	assert.match(replayScript, /旁路解密 Hook 执行失败/);
});

test('重发包使用可调整的原始请求与响应双栏工作台', () => {
    assert.match(html, /id="traffic-replay-request"[^>]+aria-label="原始 HTTP 请求"/);
    assert.match(html, /id="traffic-replay-response"/);
    assert.match(html, /id="traffic-replay-splitter"[^>]+role="separator"/);
    assert.match(html, /data-replay-response-view="raw"/);
    assert.match(html, /data-replay-response-view="body"/);
    assert.match(styles, /\.traffic-replay-workbench\s*\{[\s\S]*?grid-template-columns:[\s\S]*?min-height: 0;[\s\S]*?overflow: hidden;/);
    assert.match(styles, /\.traffic-replay-editor-shell\s*\{[\s\S]*?grid-template-columns: 46px minmax\(0, 1fr\);/);
});

test('原始请求解析会锁定原站点并由重发器管理危险请求头', () => {
    assert.match(replayScript, /function parseRawRequest\(raw\)/);
    assert.match(replayScript, /if \(url\.origin !== state\.origin\)/);
    assert.match(replayScript, /Host 由原事务锁定，不能修改/);
    assert.match(replayScript, /FORBIDDEN_HEADERS\.has\(lowerName\)/);
    assert.match(replayScript, /原始请求必须保留且只能包含一个 Host 请求头/);
});

test('重发工作台提供行号同步、快捷发送、响应指标和页面内历史', () => {
    assert.match(replayScript, /function lineNumbers\(value\)/);
    assert.match(replayScript, /traffic-replay-request-lines/);
    assert.match(replayScript, /event\.ctrlKey \|\| event\.metaKey/);
    assert.match(replayScript, /formatBytes\(byteLength\(rawResponse\)\)/);
    assert.match(replayScript, /state\.history = state\.history\.slice\(0, 20\)/);
    assert.match(replayScript, /setWorkbenchWidth/);
    assert.match(replayScript, /Connection Established/);
    assert.match(replayScript, /const interim = status >= 100 && status < 200/);
});

test('用户可手写脚本并通过隔离 Runner 验证和历史包测试', () => {
    assert.match(html, /id="traffic-transform-manual-open"/);
    assert.match(html, /def decode_request\(ctx, wire: Message\)/);
    assert.match(transformScript, /apiFetch\('\/api\/traffic-transforms\/manual'/);
    assert.match(transformScript, /roundTripMatched/);
    assert.match(transformScript, /X-Traffic-Decoded/);
});

test('脚本详情可以编辑目标网站并独立启用、停用或删除作用范围', () => {
    assert.match(html, /id="traffic-transform-scope-editor"/);
    assert.match(html, /id="traffic-transform-scope-hosts"[^>]+required/);
    assert.match(html, /id="traffic-transform-scope-priority"[^>]+min="0"[^>]+max="10000"/);
    assert.match(html, /id="traffic-transform-scope-conversation-id"/);
    assert.match(html, /id="traffic-transform-scope-activate"[^>]+checked/);
    assert.match(transformScript, /hasPermission\('traffic_transform:activate_observe'\)/);
    assert.match(transformScript, /setAttribute\('role', 'switch'\)/);
    assert.match(transformScript, /function renderScopeRows\(container, transformID\)/);
    assert.match(transformScript, /function openNewScope\(item\)/);
    assert.match(transformScript, /apiFetch\(url/);
    assert.match(transformScript, /'\/api\/traffic-transform-bindings'/);
    assert.match(transformScript, /编辑作用范围/);
    assert.match(transformScript, /traffic-transform-bindings\/\$\{encodeURIComponent\(bindingID\)\}\/scope/);
    assert.match(transformScript, /traffic-transform-bindings\/\$\{encodeURIComponent\(item\.id\)\}\/\$\{action\}/);
    assert.match(transformScript, /traffic-transform-bindings\/\$\{encodeURIComponent\(item\.id\)\}`[^\n]+method: 'DELETE'/);
    assert.match(transformScript, /脚本源码和历史运行记录会保留/);
    assert.match(transformScript, /至少填写一个目标网站/);
    assert.match(styles, /\.traffic-transform-scope-editor\s*\{/);
    assert.match(styles, /\.traffic-transform-scope-fields\s*\{/);
    assert.match(styles, /\.traffic-transform-toggle\s*\{/);
    assert.match(styles, /\.traffic-transform-scope-row\s*\{/);
});
