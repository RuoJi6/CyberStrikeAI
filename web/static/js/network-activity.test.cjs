const fs = require('node:fs');
const path = require('node:path');
const test = require('node:test');
const assert = require('node:assert/strict');

const root = path.resolve(__dirname, '..', '..', '..');
const activity = require('./network-activity.js');
const source = fs.readFileSync(path.join(root, 'web/static/js/network-activity.js'), 'utf8');
const template = fs.readFileSync(path.join(root, 'web/templates/index.html'), 'utf8');
const styles = fs.readFileSync(path.join(root, 'web/static/css/style.css'), 'utf8');
const router = fs.readFileSync(path.join(root, 'web/static/js/router.js'), 'utf8');
const zh = JSON.parse(fs.readFileSync(path.join(root, 'web/static/i18n/zh-CN.json'), 'utf8'));
const en = JSON.parse(fs.readFileSync(path.join(root, 'web/static/i18n/en-US.json'), 'utf8'));

test('SSE parser preserves split frames, event names, comments, and multi-line data', () => {
    const first = activity.parseSSEText('', ': keepalive\n\nevent: ready\ndata: {"conversationId":"c1"}\n\nevent: act');
    assert.equal(first.events.length, 1);
    assert.equal(first.events[0].event, 'ready');
    assert.equal(first.remainder, 'event: act');
    const second = activity.parseSSEText(first.remainder, 'ivity\r\ndata: {"domain":"allowed.example",\r\ndata: "decision":"allowed"}\r\n\r\n');
    assert.equal(second.remainder, '');
    assert.deepEqual(second.events, [{ event: 'activity', data: '{"domain":"allowed.example",\n"decision":"allowed"}' }]);
});

test('client activity validation and filters use closed request/decision vocabularies', () => {
    const allowed = { timestamp: '2026-08-22T12:00:00Z', requestType: 'dns', decision: 'allowed', domain: 'allowed.example', resolvedIps: ['93.184.216.34'], agent: 'container-agent', tool: '', upstreamRouteId: 'route-a' };
    const blocked = { timestamp: '2026-08-22T12:00:01Z', requestType: 'connect', decision: 'blocked', domain: 'blocked.example', connectedIp: '', agent: 'container-agent', tool: '', upstreamRouteId: '' };
    assert.equal(activity.isSafeActivityEvent(allowed), true);
    assert.equal(activity.isSafeActivityEvent({ ...allowed, requestType: 'raw-socket' }), false);
    assert.equal(activity.isSafeActivityEvent({ ...allowed, decision: '<script>' }), false);
    assert.equal(activity.isSafeActivityEvent({ ...allowed, upstreamRouteId: '<script>' }), false);
    const filtered = activity.filteredEventsForTest([allowed, blocked], { domain: '93.184', requestType: 'dns', decision: 'allowed', agent: 'container-agent', tool: 'unknown', route: 'route-a' });
    assert.deepEqual(filtered, [allowed]);
});

test('replayed Docker tail events have a stable client deduplication key', () => {
    const event = {
        timestamp: '2026-08-22T12:00:00.123456789Z', requestType: 'http', domain: 'example.com',
        port: 80, resolvedIps: ['93.184.216.34'], connectedIp: '93.184.216.34', decision: 'allowed',
        ruleId: 'allow-example', reason: 'allow-visit', method: 'GET', path: '/', httpStatus: 200,
        outcome: 'completed', latencyMs: 23, bytesDown: 559, snapshotId: 'snapshot-a',
        snapshotSha256: 'sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa',
        conversationId: 'conversation-a', agent: 'container-agent', tool: '',
    };
    assert.equal(activity.activityEventKey(event), activity.activityEventKey({ ...event }));
    assert.notEqual(activity.activityEventKey(event), activity.activityEventKey({ ...event, timestamp: '2026-08-22T12:00:01Z' }));
    assert.notEqual(activity.activityEventKey(event), activity.activityEventKey({ ...event, bytesDown: 560 }));
});

test('background gateway retries preserve a stable waiting or error badge', () => {
    assert.equal(activity.shouldShowConnectingForTest(false, 'waiting'), true);
    assert.equal(activity.shouldShowConnectingForTest(true, 'connecting'), true);
    assert.equal(activity.shouldShowConnectingForTest(true, 'waiting'), false);
    assert.equal(activity.shouldShowConnectingForTest(true, 'error'), false);
    assert.equal(activity.connectionStatusNeedsUpdateForTest('waiting', 'not_ready', 'waiting', 'not_ready'), false);
    assert.equal(activity.connectionStatusNeedsUpdateForTest('waiting', 'not_ready', 'live', ''), true);
    assert.match(source, /connectStream\(\{ retrying: true \}\)/);
    assert.ok(activity.readyStabilityMsForTest >= 100);
    assert.match(source, /if \(frame\.event === 'ready'\) scheduleReadyAnnouncement\(\)/);
    assert.match(source, /if \(frame\.event === 'stream_error'\) \{[\s\S]*?cancelReadyAnnouncement\(\)/);
});

test('network activity page is a real incremental authenticated stream UI', () => {
    for (const id of [
        'network-activity-conversation', 'network-activity-connection', 'network-activity-domain',
        'network-activity-type', 'network-activity-decision', 'network-activity-agent',
        'network-activity-tool', 'network-activity-route', 'network-activity-pause',
        'network-activity-follow', 'network-activity-clear', 'network-activity-rows',
    ]) assert.match(template, new RegExp(`id="${id}"`));
    assert.match(template, /network-activity\.js\?v=20260824-1/);
    assert.match(source, /root\.apiFetch\(url, \{ method: 'GET', headers: \{ Accept: 'text\/event-stream' \}/);
    assert.match(source, /response\.body\.getReader\(\)/);
    assert.match(source, /new AbortController\(\)/);
    assert.match(source, /Math\.min\(15000/);
    assert.match(source, /MAX_EVENTS = 500/);
    assert.match(source, /MAX_PAUSED_EVENTS = 500/);
    assert.match(source, /MAX_SEEN_EVENTS = 1000/);
    assert.doesNotMatch(source, /EventSource\s*\(/);
    assert.doesNotMatch(source, /\.innerHTML\s*=/);
    assert.match(router, /stopNetworkActivityPage\(\)/);
});

test('network activity translations and responsive card/table rules are complete', () => {
    const keys = [
        'activityStatusLive', 'activityConversation', 'activityPause', 'activityResume', 'activityFollow',
        'activityDomainPlaceholder', 'activityRequestType', 'activityDecision', 'activityAgent',
        'activityToolFilter', 'activityRouteFilter', 'activityAllowed',
        'activityBlocked', 'activityStreamTitle', 'activityEmpty', 'activitySummary', 'activityResult',
    ];
    for (const locale of [zh, en]) {
        for (const key of keys) assert.equal(typeof locale.containerManagement[key], 'string', key);
        assert.equal(typeof locale.containerManagement.activityValues.policy_denied, 'string');
        assert.equal(typeof locale.containerManagement.activityValues.tunnel_closed, 'string');
    }
    assert.match(styles, /\.network-activity-table-wrap\s*\{[\s\S]*?overflow: auto/);
    assert.match(styles, /@media \(max-width: 760px\)[\s\S]*?\.network-activity-table tr\s*\{[\s\S]*?display: grid/);
    assert.match(styles, /\.network-activity-table td::before[\s\S]*?content: attr\(data-label\)/);
});
