const fs = require('node:fs');
const test = require('node:test');
const assert = require('node:assert/strict');

const template = fs.readFileSync('web/templates/index.html', 'utf8');
const router = fs.readFileSync('web/static/js/router.js', 'utf8');
const asm = fs.readFileSync('web/static/js/asm.js', 'utf8');
const zh = JSON.parse(fs.readFileSync('web/static/i18n/zh-CN.json', 'utf8'));
const en = JSON.parse(fs.readFileSync('web/static/i18n/en-US.json', 'utf8'));

test('ASM 侧边栏是资源优先的两级折叠菜单', () => {
    const parentStart = template.indexOf('class="nav-item nav-item-has-submenu" data-page="asm"');
    const resourcesItem = template.indexOf('data-page="asm-resources"', parentStart);
    const tasksItem = template.indexOf('data-page="asm-tasks"', parentStart);

    assert.notEqual(parentStart, -1);
    assert.match(template.slice(parentStart, resourcesItem), /toggleSubmenu\('asm'\)/);
    assert.ok(resourcesItem > parentStart, 'ASM 资源应位于 ASM 父菜单中');
    assert.ok(tasksItem > resourcesItem, 'ASM 任务中心应排在 ASM 资源之后');
    assert.equal(zh.nav.asmResources, 'ASM 资源');
    assert.equal(zh.nav.asmTasks, 'ASM 任务中心');
    assert.equal(en.nav.asmResources, 'ASM Resources');
    assert.equal(en.nav.asmTasks, 'ASM Task Center');
});
test('ASM 资源和任务中心使用独立页面容器', () => {
    const resourcesStart = template.indexOf('id="page-asm-resources"');
    const tasksStart = template.indexOf('id="page-asm-tasks"');
    const projectsStart = template.indexOf('id="page-projects"');
    const resourcesPage = template.slice(resourcesStart, tasksStart);
    const tasksPage = template.slice(tasksStart, projectsStart);

    assert.ok(resourcesStart >= 0 && tasksStart > resourcesStart && projectsStart > tasksStart);
    assert.match(resourcesPage, /id="asm-resource-grid"/);
    assert.match(resourcesPage, /id="asm-resource-modal"/);
    assert.doesNotMatch(resourcesPage, /id="asm-task-list"/);
    assert.match(tasksPage, /id="asm-task-list"/);
    assert.match(tasksPage, /id="asm-task-modal"/);
    assert.doesNotMatch(tasksPage, /id="asm-resource-grid"/);
});

test('路由和页面初始化同时支持 ASM 两个子页面', () => {
    assert.match(router, /'asm-resources', 'asm-tasks'/);
    assert.match(router, /pageId === 'asm'\) pageId = 'asm-resources'/);
    assert.match(router, /pageId === 'asm-resources' \|\| pageId === 'asm-tasks'/);
    assert.match(router, /case 'asm-tasks':[\s\S]{0,180}initASMTaskCenterPage/);
    assert.match(asm, /function initASMResourcesPage\(\)[\s\S]{0,300}void loadASMResources\(\)/);
    assert.doesNotMatch(
        asm,
        /function initASMResourcesPage\(\)[\s\S]{0,300}loadASMTasks/
    );
    assert.match(asm, /async function initASMTaskCenterPage\(\)[\s\S]{0,220}await loadASMResources\(\)[\s\S]{0,160}await loadASMTasks\(true\)/);
    assert.match(asm, /window\.initASMTaskCenterPage = initASMTaskCenterPage/);
});
