const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const test = require('node:test');
const vm = require('node:vm');

const source = fs.readFileSync(path.join(__dirname, 'asm.js'), 'utf8');
const context = {
    window: {},
    console,
    URL,
    URLSearchParams,
    Set,
    Map,
    Promise,
    setTimeout,
    clearTimeout,
};

vm.runInNewContext(
    `${source}\nglobalThis.__asmTest = { asmPageState, asmRenderResultCard };`,
    context,
);

test('ARL IP assets render structured ports, ASN, and geography instead of raw JSON', () => {
    context.__asmTest.asmPageState.selectedTask = { provider: 'arl' };
    context.__asmTest.asmPageState.selectedAssetType = 'ip';

    const html = context.__asmTest.asmRenderResultCard({
        ip: '61.177.251.83',
        os_info: {
            name: 'Microsoft Windows Server 2016',
            accuracy: '100',
        },
        port_info: [
            {
                port_id: 88,
                protocol: 'tcp',
                service_name: 'http',
                product: 'Apache Tomcat',
                version: '8.5.66',
            },
        ],
        geo_asn: { number: 4134, organization: 'Chinanet' },
        geo_city: {
            city: 'Wuxi',
            region_name: 'Jiangsu',
            country_name: 'China',
            country_code: 'CN',
            latitude: 31.5618,
            longitude: 120.2864,
        },
    }, 0, []);

    const visibleContent = html.split('<details')[0];
    assert.match(visibleContent, /61\.177\.251\.83/);
    assert.match(visibleContent, /Microsoft Windows Server 2016/);
    assert.match(visibleContent, /AS4134/);
    assert.match(visibleContent, /Chinanet/);
    assert.match(visibleContent, /Wuxi · Jiangsu · China/);
    assert.match(visibleContent, />88</);
    assert.match(visibleContent, /\/tcp/);
    assert.match(visibleContent, />http</);
    assert.match(visibleContent, /Apache Tomcat 8\.5\.66/);
    assert.doesNotMatch(visibleContent, /&quot;port_id&quot;/);
    assert.doesNotMatch(visibleContent, /&quot;organization&quot;/);
    assert.match(html, /查看上游原始字段/);
});
