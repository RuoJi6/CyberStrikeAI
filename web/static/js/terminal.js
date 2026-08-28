/**
 * 系统设置 - 终端：多标签、流式输出、命令历史、Ctrl+L 清屏、长时间可取消
 */
(function () {
    var getContext = HTMLCanvasElement.prototype.getContext;
    HTMLCanvasElement.prototype.getContext = function (type, attrs) {
        if (type === '2d') {
            attrs = (attrs && typeof attrs === 'object') ? Object.assign({ willReadFrequently: true }, attrs) : { willReadFrequently: true };
            return getContext.call(this, type, attrs);
        }
        return getContext.apply(this, arguments);
    };

    var terminals = [];
    var currentTabId = 1;
    var inited = false;
    var tabIdCounter = 1;
    var PROMPT = ''; // 真实 Shell 自己输出提示符，这里不再自定义
    var HISTORY_MAX = 100;
    var CANCEL_AFTER_MS = 125000;

    function getCurrent() {
        for (var i = 0; i < terminals.length; i++) {
            if (terminals[i].id === currentTabId) return terminals[i];
        }
        return terminals[0] || null;
    }

    function tr(key, opts) {
        if (typeof window !== 'undefined' && typeof window.t === 'function') {
            return window.t(key, opts);
        }
        // i18n 未就绪时的后备（与 zh-CN 一致）
        var fallbacks = {
            'settingsTerminal.welcomeLine': 'CyberStrikeAI 终端 - 真实 Shell 会话，直接输入命令；Ctrl+L 清屏',
            'settingsTerminal.sessionClosed': '[会话已关闭]',
            'settingsTerminal.connectionError': '[终端连接出错]',
            'settingsTerminal.connectFailed': '[无法连接终端服务: {{msg}}]',
            'settingsTerminal.closeTabTitle': '关闭',
            'settingsTerminal.containerClickTitle': '点击此处后输入命令',
            'settingsTerminal.xtermNotLoaded': '未加载 xterm.js，请刷新页面或检查网络。',
            'settingsTerminal.terminalTab': '终端 {{n}}'
        };
        var s = fallbacks[key] || key;
        if (opts && typeof opts === 'object') {
            Object.keys(opts).forEach(function (k) {
                s = s.split('{{' + k + '}}').join(String(opts[k]));
            });
        }
        return s;
    }

    function getWelcomeLine(tab) {
        if (tab && tab.options && typeof tab.options.welcomeLine === 'function') {
            return String(tab.options.welcomeLine()) + '\r\n';
        }
        if (tab && tab.options && tab.options.welcomeLine) {
            return String(tab.options.welcomeLine) + '\r\n';
        }
        return tr('settingsTerminal.welcomeLine') + '\r\n';
    }

    function writePrompt(tab) {
        // 提示符交由后端 Shell 自行输出，这里仅保留占位函数，避免旧代码报错
    }

    function redrawTabDisplay(t) {
        if (!t || !t.term) return;
        t.term.clear();
        t.term.write(getWelcomeLine(t));
    }

    function writeln(tabOrS, s) {
        var t, text;
        if (arguments.length === 1) { text = tabOrS; t = getCurrent(); } else { t = tabOrS; text = s; }
        if (!t || !t.term) return;
        if (text) t.term.writeln(text);
        else t.term.writeln('');
    }

    function writeTermData(tab, data) {
        if (!tab || !tab.term || data === undefined || data === null) return;
        try {
            tab.term.write(data, function () {
                try { tab.term.scrollToBottom(); } catch (e) {}
            });
        } catch (e) {
            tab.term.write(data);
        }
    }

    function writeOutput(tab, text, isError) {
        var t = tab || getCurrent();
        if (!t || !t.term || !text) return;
        var s = String(text).replace(/\r\n/g, '\n').replace(/\r/g, '\n');
        var lines = s.split('\n');
        var prefix = isError ? '\x1b[31m' : '';
        var suffix = isError ? '\x1b[0m' : '';
        t.term.write(prefix);
        for (var i = 0; i < lines.length; i++) {
            var line = lines[i].replace(/\r/g, '');
            t.term.writeln(line);
        }
        t.term.write(suffix);
    }

    // 从本地存储中获取当前登录 token（与 auth.js 使用的结构保持一致）
    function getStoredAuthToken() {
        try {
            var raw = localStorage.getItem('cyberstrike-auth');
            if (!raw) return null;
            var o = JSON.parse(raw);
            if (o && o.token) return o.token;
        } catch (e) {}
        return null;
    }

    // WebSocket 地址构造（兼容 http/https，并通过 query 传递 token 以通过后端鉴权）
    function buildTerminalWSURL() {
        var proto = (window.location.protocol === 'https:') ? 'wss://' : 'ws://';
        var url = proto + window.location.host + '/api/terminal/ws';
        var token = getStoredAuthToken();
        if (token) {
            url += '?token=' + encodeURIComponent(token);
        }
        return url;
    }

    function buildAuthenticatedWSURL(pathname) {
        var proto = (window.location.protocol === 'https:') ? 'wss://' : 'ws://';
        var url = proto + window.location.host + String(pathname || '');
        var token = getStoredAuthToken();
        if (token) url += (url.indexOf('?') >= 0 ? '&' : '?') + 'token=' + encodeURIComponent(token);
        return url;
    }

    function ensureTerminalWS(tab) {
        if (tab.ws && (tab.ws.readyState === WebSocket.OPEN || tab.ws.readyState === WebSocket.CONNECTING)) {
            return;
        }
        try {
            var wsURL = tab.options && typeof tab.options.buildWSURL === 'function'
                ? tab.options.buildWSURL()
                : buildTerminalWSURL();
            var ws = new WebSocket(wsURL);
            tab.ws = ws;
            tab.running = true;

            ws.onopen = function () {
                if (tab.options && typeof tab.options.onConnectionState === 'function') tab.options.onConnectionState('open');
                if (tab.term) {
                    tab.term.focus();
                    // Send the actual terminal dimensions to the backend immediately
                    // so the PTY size matches what xterm.js is displaying.
                    if (tab.term.cols && tab.term.rows) {
                        try {
                            ws.send(JSON.stringify({ type: 'resize', cols: tab.term.cols, rows: tab.term.rows }));
                        } catch (e) {}
                    }
                }
            };

            ws.onmessage = function (ev) {
                if (!tab.term) return;
                // 处理二进制消息和文本消息
                if (ev.data instanceof ArrayBuffer) {
                    var decoder = new TextDecoder('utf-8');
                    writeTermData(tab, decoder.decode(ev.data));
                } else if (ev.data instanceof Blob) {
                    // Blob 类型，需要异步读取
                    var reader = new FileReader();
                    reader.onload = function () {
                        var decoder = new TextDecoder('utf-8');
                        writeTermData(tab, decoder.decode(reader.result));
                    };
                    reader.readAsArrayBuffer(ev.data);
                } else {
                    // 字符串类型
                    writeTermData(tab, ev.data);
                }
            };

            ws.onclose = function () {
                tab.running = false;
                if (tab.options && typeof tab.options.onConnectionState === 'function') tab.options.onConnectionState('closed');
                if (tab.term) {
                    tab.term.writeln('\r\n\x1b[2m' + tr('settingsTerminal.sessionClosed') + '\x1b[0m');
                }
            };

            ws.onerror = function () {
                tab.running = false;
                if (tab.options && typeof tab.options.onConnectionState === 'function') tab.options.onConnectionState('error');
                if (tab.term) {
                    tab.term.writeln('\r\n\x1b[31m' + tr('settingsTerminal.connectionError') + '\x1b[0m');
                }
            };
        } catch (e) {
            if (tab.term) {
                tab.term.writeln('\r\n\x1b[31m' + tr('settingsTerminal.connectFailed', { msg: String(e) }) + '\x1b[0m');
            }
        }
    }

    function createTerminalInContainer(container, tab) {
        if (typeof Terminal === 'undefined') return null;
        if (!tab.history) tab.history = [];
        if (tab.historyIndex === undefined) tab.historyIndex = -1;
        if (tab.cursorIndex === undefined) tab.cursorIndex = 0;

        var term = new Terminal({
            cursorBlink: true,
            cursorStyle: 'bar',
            fontSize: 13,
            fontFamily: 'Menlo, Monaco, "Courier New", monospace',
            lineHeight: 1.2,
            smoothScrollDuration: 0,
            scrollSensitivity: 1,
            fastScrollSensitivity: 5,
            scrollback: 1000,
            theme: {
                background: '#0d1117',
                foreground: '#e6edf3',
                cursor: '#58a6ff',
                cursorAccent: '#0d1117',
                selection: 'rgba(88, 166, 255, 0.3)',
                black: '#484f58',
                red: '#ff7b72',
                green: '#3fb950',
                yellow: '#d29922',
                blue: '#58a6ff',
                magenta: '#bc8cff',
                cyan: '#39c5cf',
                white: '#e6edf3',
                brightBlack: '#6e7681',
                brightRed: '#ffa198',
                brightGreen: '#56d364',
                brightYellow: '#e3b341',
                brightBlue: '#79c0ff',
                brightMagenta: '#d2a8ff',
                brightCyan: '#56d4dd',
                brightWhite: '#f0f6fc'
            }
        });
        var fitAddon = null;
        if (typeof FitAddon !== 'undefined') {
            var FitCtor = (FitAddon.FitAddon || FitAddon);
            fitAddon = new FitCtor();
            term.loadAddon(fitAddon);
        }
        term.open(container);
        term.write(getWelcomeLine(tab));
        container.addEventListener('click', function () {
            if (tab.options && typeof tab.options.activate === 'function') tab.options.activate();
            else switchTerminalTab(tab.id);
            if (term) term.focus();
        });
        container.setAttribute('tabindex', '0');
        container.title = tr('settingsTerminal.containerClickTitle');

        function sendToWS(data) {
            ensureTerminalWS(tab);
            if (tab.ws && tab.ws.readyState === WebSocket.OPEN) {
                try {
                    tab.ws.send(data);
                } catch (e) {}
            }
        }

        function sendResize() {
            if (tab.ws && tab.ws.readyState === WebSocket.OPEN && term.cols && term.rows) {
                try {
                    tab.ws.send(JSON.stringify({ type: 'resize', cols: term.cols, rows: term.rows }));
                } catch (e) {}
            }
        }

        // xterm normally turns Tab into \t, but browsers can consume it as
        // focus navigation before onData fires (especially inside a drawer).
        // Handle it explicitly and send the completion key to the container
        // PTY. Shift+Tab keeps the standard reverse-completion sequence.
        if (typeof term.attachCustomKeyEventHandler === 'function') {
            term.attachCustomKeyEventHandler(function (event) {
                if (!event || event.key !== 'Tab') return true;
                if (event.type === 'keydown') {
                    if (typeof event.preventDefault === 'function') event.preventDefault();
                    if (typeof event.stopPropagation === 'function') event.stopPropagation();
                    sendToWS(event.shiftKey ? '\x1b[Z' : '\t');
                }
                return false;
            });
        }

        term.onData(function (data) {
            // Ctrl+L：本地清屏，同时把 ^L 也发给后端
            if (data === '\x0c') {
                term.clear();
                sendToWS(data);
                return;
            }
            sendToWS(data);
        });

        // Notify backend when the terminal is resized so the PTY dimensions stay in sync.
        // This is critical for full-screen programs like vi/vim/less to render correctly.
        term.onResize(function (size) {
            sendResize();
        });

        tab.term = term;
        tab.fitAddon = fitAddon;
        if (typeof ResizeObserver !== 'undefined' && fitAddon) {
            var resizeTimer;
            tab.resizeObserver = new ResizeObserver(function () {
                clearTimeout(resizeTimer);
                resizeTimer = setTimeout(function () {
                    try {
                        fitAddon.fit();
                        term.scrollToBottom();
                    } catch (e) {}
                }, 50);
            });
            tab.resizeObserver.observe(container);
        }
        // 立即建立 WebSocket，让后端 PTY/Shell 马上启动并输出提示符；
        // 若等到首次按键才 connect，用户会感觉必须先按回车才能输入（实为连接尚未建立）。
        ensureTerminalWS(tab);
        return term;
    }

    function switchTerminalTab(id) {
        var prevId = currentTabId;
        currentTabId = id;
        document.querySelectorAll('.terminal-tab').forEach(function (el) {
            el.classList.toggle('active', parseInt(el.getAttribute('data-tab-id'), 10) === id);
        });
        document.querySelectorAll('.terminal-pane').forEach(function (el) {
            var paneId = el.getAttribute('id');
            var match = paneId && paneId.match(/terminal-pane-(\d+)/);
            var paneTabId = match ? parseInt(match[1], 10) : 0;
            el.classList.toggle('active', paneTabId === id);
        });
        var t = getCurrent();
        if (t && t.term) {
            try {
                if (t.fitAddon) t.fitAddon.fit();
                t.term.scrollToBottom();
            } catch (e) {}
            if (prevId !== id) {
                requestAnimationFrame(function () {
                    if (currentTabId === id && t.term) {
                        try {
                            if (t.fitAddon) t.fitAddon.fit();
                            t.term.scrollToBottom();
                        } catch (e) {}
                        t.term.focus();
                    }
                });
            } else {
                t.term.focus();
            }
        }
    }

    function addTerminalTab() {
        if (typeof Terminal === 'undefined') return;
        tabIdCounter += 1;
        var id = tabIdCounter;
        var paneId = 'terminal-pane-' + id;
        var containerId = 'terminal-container-' + id;
        var tabsEl = document.querySelector('.terminal-tabs');
        var panesEl = document.querySelector('.terminal-panes');
        if (!tabsEl || !panesEl) return;

        var tabDiv = document.createElement('div');
        tabDiv.className = 'terminal-tab';
        tabDiv.setAttribute('data-tab-id', String(id));
        var label = document.createElement('span');
        label.className = 'terminal-tab-label';
        label.textContent = tr('settingsTerminal.terminalTab', { n: id });
        label.onclick = function () { switchTerminalTab(id); };
        var closeBtn = document.createElement('button');
        closeBtn.type = 'button';
        closeBtn.className = 'terminal-tab-close';
        closeBtn.title = tr('settingsTerminal.closeTabTitle');
        closeBtn.textContent = '×';
        closeBtn.onclick = function (e) { e.stopPropagation(); removeTerminalTab(id); };
        tabDiv.appendChild(label);
        tabDiv.appendChild(closeBtn);
        var plusBtn = tabsEl.querySelector('.terminal-tab-new');
        tabsEl.insertBefore(tabDiv, plusBtn);

        var paneDiv = document.createElement('div');
        paneDiv.id = paneId;
        paneDiv.className = 'terminal-pane';
        var containerDiv = document.createElement('div');
        containerDiv.id = containerId;
        containerDiv.className = 'terminal-container';
        paneDiv.appendChild(containerDiv);
        panesEl.appendChild(paneDiv);

        var tab = { id: id, paneId: paneId, containerId: containerId, lineBuffer: '', cursorIndex: 0, running: false, term: null, fitAddon: null, history: [], historyIndex: -1 };
        terminals.push(tab);
        createTerminalInContainer(containerDiv, tab);
        switchTerminalTab(id);
        updateTerminalTabCloseVisibility();
        setTimeout(function () {
            try { if (tab.fitAddon) tab.fitAddon.fit(); if (tab.term) tab.term.focus(); } catch (e) {}
        }, 50);
    }

    function updateTerminalTabCloseVisibility() {
        var tabsEl = document.querySelector('.terminal-tabs');
        if (!tabsEl) return;
        var tabDivs = tabsEl.querySelectorAll('.terminal-tab');
        var showClose = terminals.length > 1;
        for (var i = 0; i < tabDivs.length; i++) {
            var btn = tabDivs[i].querySelector('.terminal-tab-close');
            if (btn) btn.style.display = showClose ? '' : 'none';
        }
    }

    function removeTerminalTab(id) {
        if (terminals.length <= 1) return;
        var idx = -1;
        for (var i = 0; i < terminals.length; i++) { if (terminals[i].id === id) { idx = i; break; } }
        if (idx < 0) return;

        var deletingCurrent = (currentTabId === id);
        var switchToIndex = deletingCurrent ? (idx > 0 ? idx - 1 : 0) : -1;

        var tab = terminals[idx];
        if (tab.ws) {
            try { tab.ws.close(); } catch (e) {}
            tab.ws = null;
        }
        if (tab.resizeObserver && tab.resizeObserver.disconnect) tab.resizeObserver.disconnect();
        if (tab.term && tab.term.dispose) tab.term.dispose();
        tab.term = null;
        tab.fitAddon = null;
        tab.resizeObserver = null;
        terminals.splice(idx, 1);

        var tabDiv = document.querySelector('.terminal-tab[data-tab-id="' + id + '"]');
        var paneDiv = document.getElementById('terminal-pane-' + id);
        if (tabDiv && tabDiv.parentNode) tabDiv.parentNode.removeChild(tabDiv);
        if (paneDiv && paneDiv.parentNode) paneDiv.parentNode.removeChild(paneDiv);

        var curIdxBeforeRenumber = -1;
        if (!deletingCurrent) {
            for (var i = 0; i < terminals.length; i++) {
                if (terminals[i].id === currentTabId) { curIdxBeforeRenumber = i; break; }
            }
        }

        for (var i = 0; i < terminals.length; i++) {
            var t = terminals[i];
            t.id = i + 1;
            t.paneId = 'terminal-pane-' + (i + 1);
            t.containerId = 'terminal-container-' + (i + 1);
        }
        tabIdCounter = terminals.length;
        if (curIdxBeforeRenumber >= 0) currentTabId = terminals[curIdxBeforeRenumber].id;

        var tabsEl = document.querySelector('.terminal-tabs');
        var panesEl = document.querySelector('.terminal-panes');
        if (tabsEl) {
            var tabDivs = tabsEl.querySelectorAll('.terminal-tab');
            for (var i = 0; i < tabDivs.length; i++) {
                var t = terminals[i];
                tabDivs[i].setAttribute('data-tab-id', String(t.id));
                var lbl = tabDivs[i].querySelector('.terminal-tab-label');
                if (lbl) lbl.textContent = tr('settingsTerminal.terminalTab', { n: t.id });
                if (lbl) lbl.onclick = (function (tid) { return function () { switchTerminalTab(tid); }; })(t.id);
                var cb = tabDivs[i].querySelector('.terminal-tab-close');
                if (cb) cb.onclick = (function (tid) { return function (e) { e.stopPropagation(); removeTerminalTab(tid); }; })(t.id);
            }
        }
        if (panesEl) {
            var paneDivs = panesEl.querySelectorAll('.terminal-pane');
            for (var i = 0; i < paneDivs.length; i++) {
                var t = terminals[i];
                paneDivs[i].id = t.paneId;
                var cont = paneDivs[i].querySelector('.terminal-container');
                if (cont) cont.id = t.containerId;
            }
        }

        updateTerminalTabCloseVisibility();

        if (deletingCurrent && terminals.length > 0) {
            currentTabId = terminals[switchToIndex].id;
            switchTerminalTab(currentTabId);
        }
    }

    function escapeHtml(s) {
        return String(s)
            .replace(/&/g, '&amp;')
            .replace(/</g, '&lt;')
            .replace(/>/g, '&gt;')
            .replace(/"/g, '&quot;');
    }

    function refreshTerminalI18n() {
        // 语言切换后更新标签与容器 title；已打开的终端内容不强制清屏，以免丢失会话输出
        try {
            var tabsEl = document.querySelector('.terminal-tabs');
            if (tabsEl) {
                var tabDivs = tabsEl.querySelectorAll('.terminal-tab');
                for (var i = 0; i < tabDivs.length && i < terminals.length; i++) {
                    var tid = terminals[i].id;
                    var lbl = tabDivs[i].querySelector('.terminal-tab-label');
                    if (lbl) lbl.textContent = tr('settingsTerminal.terminalTab', { n: tid });
                    var cb = tabDivs[i].querySelector('.terminal-tab-close');
                    if (cb) cb.title = tr('settingsTerminal.closeTabTitle');
                }
            }
            terminals.forEach(function (tab) {
                if (!tab || !tab.term) return;
                var cont = document.getElementById(tab.containerId);
                if (cont) cont.title = tr('settingsTerminal.containerClickTitle');
            });
        } catch (e) { /* ignore */ }
    }

    document.addEventListener('languagechange', function () {
        refreshTerminalI18n();
    });

    function initTerminal() {
        var pane1 = document.getElementById('terminal-pane-1');
        var container1 = document.getElementById('terminal-container-1');
        if (!pane1 || !container1) return;
        if (inited) {
            var t = getCurrent();
            if (t && t.term) t.term.focus();
            terminals.forEach(function (tab) { try { if (tab.fitAddon) tab.fitAddon.fit(); } catch (e) {} });
            return;
        }
        inited = true;

        if (typeof Terminal === 'undefined') {
            container1.innerHTML = '<p class="terminal-error">' + escapeHtml(tr('settingsTerminal.xtermNotLoaded')) + '</p>';
            return;
        }

        currentTabId = 1;
        var tab = { id: 1, paneId: 'terminal-pane-1', containerId: 'terminal-container-1', lineBuffer: '', cursorIndex: 0, running: false, term: null, fitAddon: null, history: [], historyIndex: -1 };
        terminals.push(tab);
        createTerminalInContainer(container1, tab);

        updateTerminalTabCloseVisibility();

        refreshTerminalI18n();

        setTimeout(function () {
            try { if (tab.fitAddon) tab.fitAddon.fit(); if (tab.term) tab.term.focus(); } catch (e) {}
        }, 100);

        var resizeTimer;
        window.addEventListener('resize', function () {
            clearTimeout(resizeTimer);
            resizeTimer = setTimeout(function () {
                terminals.forEach(function (t) { try { if (t.fitAddon) t.fitAddon.fit(); } catch (e) {} });
            }, 150);
        });
    }

    function terminalClear() {
        var t = getCurrent();
        if (!t || !t.term) return;
        t.term.clear();
        t.lineBuffer = '';
        if (t.cursorIndex !== undefined) t.cursorIndex = 0;
        writePrompt(t);
        t.term.focus();
    }

    var embeddedTerminalWorkspaceCounter = 0;

    // Shared xterm workspace used by the chat and container-management views.
    // The caller supplies only a WebSocket URL builder; keyboard handling,
    // sizing, theming, tabs, and lifecycle remain identical to Settings.
    function createEmbeddedTerminal(root, options) {
        if (!root) return null;
        options = options || {};
        embeddedTerminalWorkspaceCounter += 1;
        var workspaceId = embeddedTerminalWorkspaceCounter;
        var embeddedTabs = [];
        var activeId = 0;
        var nextId = 0;

        root.replaceChildren();
        var wrapper = document.createElement('div');
        wrapper.className = 'terminal-wrapper embedded-terminal-wrapper';
        var tabsBar = document.createElement('div');
        tabsBar.className = 'terminal-tabs';
        var addButton = document.createElement('button');
        addButton.type = 'button';
        addButton.className = 'terminal-tab-new';
        addButton.textContent = '+';
        addButton.title = options.newTabTitle || tr('settingsTerminal.newTerminal');
        var panes = document.createElement('div');
        panes.className = 'terminal-panes';
        tabsBar.append(addButton);
        wrapper.append(tabsBar, panes);
        root.append(wrapper);

        function labelFor(index) {
            if (typeof options.tabLabel === 'function') return String(options.tabLabel(index));
            return String(options.tabLabel || tr('settingsTerminal.terminalTab', { n: index }));
        }

        function updateCloseButtons() {
            var show = embeddedTabs.length > 1;
            embeddedTabs.forEach(function (tab) {
                if (tab.closeButton) tab.closeButton.hidden = !show;
            });
        }

        function activate(id) {
            activeId = id;
            embeddedTabs.forEach(function (tab) {
                var selected = tab.id === id;
                tab.tabElement.classList.toggle('active', selected);
                tab.pane.classList.toggle('active', selected);
                if (selected && tab.term) {
                    requestAnimationFrame(function () {
                        try {
                            if (tab.fitAddon) tab.fitAddon.fit();
                            tab.term.scrollToBottom();
                            tab.term.focus();
                        } catch (e) {}
                    });
                }
            });
        }

        function destroyTab(tab) {
            if (!tab) return;
            if (tab.resizeObserver && tab.resizeObserver.disconnect) tab.resizeObserver.disconnect();
            tab.resizeObserver = null;
            if (tab.term && tab.term.dispose) tab.term.dispose();
            tab.term = null;
            tab.fitAddon = null;
            if (tab.ws) {
                try { tab.ws.close(); } catch (e) {}
                tab.ws = null;
            }
            if (tab.tabElement && tab.tabElement.parentNode) tab.tabElement.parentNode.removeChild(tab.tabElement);
            if (tab.pane && tab.pane.parentNode) tab.pane.parentNode.removeChild(tab.pane);
        }

        function remove(id) {
            if (embeddedTabs.length <= 1) return;
            var index = embeddedTabs.findIndex(function (tab) { return tab.id === id; });
            if (index < 0) return;
            var wasActive = activeId === id;
            var tab = embeddedTabs[index];
            embeddedTabs.splice(index, 1);
            destroyTab(tab);
            if (wasActive) activate(embeddedTabs[Math.max(0, index - 1)].id);
            updateCloseButtons();
        }

        function add() {
            nextId += 1;
            var id = nextId;
            var tabElement = document.createElement('div');
            tabElement.className = 'terminal-tab';
            tabElement.dataset.embeddedTerminalTab = String(workspaceId) + '-' + String(id);
            var label = document.createElement('button');
            label.type = 'button';
            label.className = 'terminal-tab-label embedded-terminal-tab-label';
            label.textContent = labelFor(embeddedTabs.length + 1);
            label.addEventListener('click', function () { activate(id); });
            var closeButton = document.createElement('button');
            closeButton.type = 'button';
            closeButton.className = 'terminal-tab-close';
            closeButton.title = tr('settingsTerminal.closeTabTitle');
            closeButton.textContent = '×';
            closeButton.addEventListener('click', function (event) {
                event.stopPropagation();
                remove(id);
            });
            tabElement.append(label, closeButton);
            tabsBar.insertBefore(tabElement, addButton);

            var pane = document.createElement('div');
            pane.className = 'terminal-pane';
            var container = document.createElement('div');
            container.className = 'terminal-container';
            pane.append(container);
            panes.append(pane);

            var tab = {
                id: id,
                pane: pane,
                tabElement: tabElement,
                closeButton: closeButton,
                running: false,
                term: null,
                fitAddon: null,
                history: [],
                historyIndex: -1,
                options: {
                    buildWSURL: options.buildWSURL,
                    welcomeLine: options.welcomeLine,
                    activate: function () { activate(id); },
                    onConnectionState: function (state) {
                        if (typeof options.onConnectionState === 'function') options.onConnectionState(state, id);
                    }
                }
            };
            embeddedTabs.push(tab);
            createTerminalInContainer(container, tab);
            activate(id);
            updateCloseButtons();
            return tab;
        }

        addButton.addEventListener('click', add);
        add();

        return {
            addTab: add,
            focus: function () { activate(activeId); },
            fit: function () {
                embeddedTabs.forEach(function (tab) {
                    try { if (tab.fitAddon) tab.fitAddon.fit(); } catch (e) {}
                });
            },
            dispose: function () {
                embeddedTabs.slice().forEach(destroyTab);
                embeddedTabs = [];
                root.replaceChildren();
            }
        };
    }

    window.initTerminal = initTerminal;
    window.terminalClear = terminalClear;
    window.switchTerminalTab = switchTerminalTab;
    window.addTerminalTab = addTerminalTab;
    window.removeTerminalTab = removeTerminalTab;
    window.CyberStrikeTerminal = {
        createEmbeddedTerminal: createEmbeddedTerminal,
        buildAuthenticatedWSURL: buildAuthenticatedWSURL,
    };
})();
