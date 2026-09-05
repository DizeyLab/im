//! The themed dropdown, ported from izlek's `dropdown.rs`: a native
//! `<select>`'s popup follows the browser's chrome, not the design — only
//! Chromium's `::picker(select)` themes it, Firefox and WebKit never see it.
//! So every `select.auth-input` is progressively enhanced: the native
//! element stays in the DOM hidden (its `name` and value still post
//! unchanged) while a trigger button and a portaled, fixed-position panel
//! take over the look. A pick writes the native select and dispatches a
//! bubbling `change`, which is what the soft-nav's `data-autosubmit`
//! listener turns into a filter submit — zero extra wiring.
//!
//! Unlike izlek's, this port needs no node-ownership registry: im's soft
//! swap rebuilds `<body>` wholesale, client-made nodes die with it, and the
//! fresh select is simply enhanced again — `enhanceAll` runs on every
//! evaluation and through `window.__imDdEnhance` after every adopt.

use topcoat::Result;
use topcoat::context::Cx;
use topcoat::view::{Unescaped, view};

pub async fn dropdown_script(cx: &Cx) -> Result {
    const JS: &str = "\
        (function () {\
            function enhanceAll() { document.querySelectorAll('select.auth-input').forEach(enhance); }\
            window.__imDdEnhance = enhanceAll;\
            if (window.__imDd) { enhanceAll(); return; }\
            window.__imDd = true;\
            function opts(select) { return Array.prototype.slice.call(select.options); }\
            function closeAll() {\
                document.querySelectorAll('.dd-panel.dd-open').forEach(function (panel) {\
                    panel.classList.remove('dd-open');\
                    if (panel.__ddTrigger) { panel.__ddTrigger.setAttribute('aria-expanded', 'false'); }\
                });\
            }\
            function place(panel, trigger) {\
                var r = trigger.getBoundingClientRect();\
                var h = panel.offsetHeight;\
                var w = panel.offsetWidth;\
                var top = r.bottom + 4;\
                if (top + h > window.innerHeight && r.top - h - 4 >= 0) { top = r.top - h - 4; }\
                top = Math.max(4, Math.min(top, window.innerHeight - h - 4));\
                var left = Math.max(4, Math.min(r.left, window.innerWidth - w - 4));\
                panel.style.left = left + 'px';\
                panel.style.top = top + 'px';\
                panel.style.minWidth = r.width + 'px';\
            }\
            function visibleRows(panel) { return Array.prototype.slice.call(panel.querySelectorAll('.dd-option:not(.dd-option-hidden)')); }\
            function activate(panel, row) {\
                panel.querySelectorAll('.dd-option-active').forEach(function (r) { r.classList.remove('dd-option-active'); });\
                if (!row) { return; }\
                row.classList.add('dd-option-active');\
                if (panel.__ddSearch) { row.scrollIntoView({ block: 'nearest' }); } else { row.focus(); }\
            }\
            function isTypeKey(e) { return e.key && e.key.length === 1 && !e.ctrlKey && !e.altKey && !e.metaKey; }\
            function typeIntoSearch(search, e) {\
                search.focus();\
                search.value += e.key;\
                search.dispatchEvent(new Event('input', { bubbles: true }));\
            }\
            function filterRows(panel, query) {\
                var qTr = query.toLocaleLowerCase('tr');\
                var qEn = query.toLowerCase();\
                panel.querySelectorAll('.dd-option').forEach(function (r) {\
                    var t = r.textContent;\
                    var miss = t.toLocaleLowerCase('tr').indexOf(qTr) === -1 && t.toLowerCase().indexOf(qEn) === -1;\
                    r.classList.toggle('dd-option-hidden', qEn !== '' && miss);\
                });\
                var vis = visibleRows(panel);\
                activate(panel, panel.querySelector('.dd-option-selected:not(.dd-option-hidden)') || vis[0]);\
            }\
            function pick(select, trigger, panel, row) {\
                select.value = row.dataset.value;\
                panel.querySelectorAll('.dd-option').forEach(function (r) {\
                    r.classList.toggle('dd-option-selected', r === row);\
                    r.setAttribute('aria-selected', r === row ? 'true' : 'false');\
                });\
                trigger.textContent = row.textContent;\
                panel.classList.remove('dd-open');\
                trigger.setAttribute('aria-expanded', 'false');\
                trigger.focus();\
                select.dispatchEvent(new Event('change', { bubbles: true }));\
            }\
            function openPanel(select, trigger, panel) {\
                closeAll();\
                var search = panel.__ddSearch;\
                if (search) {\
                    search.value = '';\
                    panel.querySelectorAll('.dd-option').forEach(function (r) { r.classList.remove('dd-option-hidden'); });\
                }\
                panel.classList.add('dd-open');\
                place(panel, trigger);\
                trigger.setAttribute('aria-expanded', 'true');\
                activate(panel, panel.querySelector('.dd-option-selected') || panel.querySelector('.dd-option'));\
                if (search) { search.focus(); }\
            }\
            function fillRows(panel, select) {\
                panel.querySelectorAll('.dd-option').forEach(function (r) { r.remove(); });\
                opts(select).forEach(function (opt) {\
                    var row = document.createElement('button');\
                    row.type = 'button';\
                    row.className = 'dd-option' + (opt.selected ? ' dd-option-selected' : '');\
                    row.textContent = opt.textContent;\
                    row.dataset.value = opt.value;\
                    row.setAttribute('role', 'option');\
                    row.setAttribute('aria-selected', opt.selected ? 'true' : 'false');\
                    panel.appendChild(row);\
                });\
            }\
            function rowsMatch(panel, select) {\
                var rows = panel.querySelectorAll('.dd-option');\
                var all = opts(select);\
                if (rows.length !== all.length) { return false; }\
                for (var i = 0; i < all.length; i++) {\
                    if (rows[i].dataset.value !== all[i].value) { return false; }\
                    if (rows[i].textContent !== all[i].textContent) { return false; }\
                }\
                return true;\
            }\
            function resync(select) {\
                var trigger = select.__ddTrigger, panel = select.__ddPanel;\
                if (!trigger || !panel) { return; }\
                select.classList.add('dd-native');\
                if (panel.classList.contains('dd-open')) { return; }\
                if (!rowsMatch(panel, select)) { fillRows(panel, select); }\
                var current = select.options[select.selectedIndex];\
                var label = current ? current.textContent : '';\
                if (trigger.textContent !== label) { trigger.textContent = label; }\
                panel.querySelectorAll('.dd-option').forEach(function (r) {\
                    var on = !!current && r.dataset.value === current.value;\
                    r.classList.toggle('dd-option-selected', on);\
                    r.setAttribute('aria-selected', on ? 'true' : 'false');\
                });\
            }\
            function enhance(select) {\
                if (select.dataset.ddDone) { resync(select); return; }\
                select.dataset.ddDone = '1';\
                var trigger = document.createElement('button');\
                trigger.type = 'button';\
                trigger.className = select.className + ' dd-trigger';\
                var current = select.options[select.selectedIndex];\
                trigger.textContent = current ? current.textContent : '';\
                trigger.setAttribute('aria-haspopup', 'listbox');\
                trigger.setAttribute('aria-expanded', 'false');\
                select.parentNode.insertBefore(trigger, select);\
                select.classList.add('dd-native');\
                var panel = document.createElement('div');\
                panel.className = 'dd-panel';\
                panel.setAttribute('role', 'listbox');\
                panel.__ddTrigger = trigger;\
                trigger.__ddPanel = panel;\
                trigger.__ddSelect = select;\
                select.__ddTrigger = trigger;\
                select.__ddPanel = panel;\
                var allOpts = opts(select);\
                var search = null;\
                if (allOpts.length > 7 || select.hasAttribute('data-search')) {\
                    search = document.createElement('input');\
                    search.type = 'text';\
                    search.className = 'dd-search';\
                    panel.appendChild(search);\
                    panel.__ddSearch = search;\
                }\
                fillRows(panel, select);\
                document.body.appendChild(panel);\
                trigger.addEventListener('click', function (e) {\
                    e.stopPropagation();\
                    if (panel.classList.contains('dd-open')) { closeAll(); } else { openPanel(select, trigger, panel); }\
                });\
                trigger.addEventListener('keydown', function (e) {\
                    if (e.key === 'ArrowDown' || e.key === 'ArrowUp') {\
                        e.preventDefault();\
                        if (!panel.classList.contains('dd-open')) { openPanel(select, trigger, panel); return; }\
                        var vis = visibleRows(panel);\
                        var idx = vis.indexOf(panel.querySelector('.dd-option-active')) + (e.key === 'ArrowDown' ? 1 : -1);\
                        if (idx >= 0 && idx < vis.length) { activate(panel, vis[idx]); }\
                    } else if (e.key === 'Enter' && panel.classList.contains('dd-open')) {\
                        e.preventDefault();\
                        var active = panel.querySelector('.dd-option-active');\
                        if (active) { pick(select, trigger, panel, active); }\
                    } else if (search && isTypeKey(e)) {\
                        e.preventDefault();\
                        if (!panel.classList.contains('dd-open')) { openPanel(select, trigger, panel); }\
                        typeIntoSearch(search, e);\
                    }\
                });\
                if (search) {\
                    search.addEventListener('input', function () { filterRows(panel, search.value); });\
                }\
                panel.addEventListener('keydown', function (e) {\
                    if (e.key === 'ArrowDown' || e.key === 'ArrowUp') {\
                        e.preventDefault();\
                        var vis = visibleRows(panel);\
                        var idx = vis.indexOf(panel.querySelector('.dd-option-active')) + (e.key === 'ArrowDown' ? 1 : -1);\
                        if (idx >= 0 && idx < vis.length) { activate(panel, vis[idx]); }\
                    } else if (e.key === 'Enter') {\
                        e.preventDefault();\
                        var vis = visibleRows(panel);\
                        var active = panel.querySelector('.dd-option-active') || (vis.length === 1 ? vis[0] : null);\
                        if (active) { pick(select, trigger, panel, active); }\
                    } else if (search && e.target !== search && isTypeKey(e)) {\
                        e.preventDefault();\
                        typeIntoSearch(search, e);\
                    }\
                });\
                panel.addEventListener('click', function (e) {\
                    e.stopPropagation();\
                    var row = e.target.closest('.dd-option');\
                    if (row) { pick(select, trigger, panel, row); }\
                });\
            }\
            document.addEventListener('keydown', function (e) {\
                if (e.key !== 'Escape') { return; }\
                var panel = document.querySelector('.dd-panel.dd-open');\
                if (!panel) { return; }\
                var trigger = panel.__ddTrigger;\
                closeAll();\
                if (trigger) { trigger.focus(); }\
            });\
            document.addEventListener('click', function (e) {\
                var el = e.target;\
                if (!el || !el.closest) { return; }\
                if (el.closest('.dd-panel') || el.closest('.dd-trigger')) { return; }\
                if (el.closest('a, button, input:not([type=hidden]), textarea')) { return; }\
                var box = el.nodeType === 1 ? el : el.parentNode;\
                for (var depth = 0; depth < 3 && box && box.querySelectorAll; depth++) {\
                    var found = box.querySelectorAll('.dd-trigger');\
                    if (found.length === 1 && found[0].parentNode === box && found[0].__ddPanel) {\
                        var t = found[0];\
                        e.stopPropagation();\
                        e.preventDefault();\
                        if (t.__ddPanel.classList.contains('dd-open')) { closeAll(); }\
                        else { openPanel(t.__ddSelect, t, t.__ddPanel); }\
                        return;\
                    }\
                    box = box.parentNode;\
                }\
            }, true);\
            document.addEventListener('click', closeAll);\
            window.addEventListener('scroll', function (e) {\
                var t = e.target;\
                if (t && t.nodeType === 1 && t.classList.contains('dd-panel')) { return; }\
                closeAll();\
            }, true);\
            enhanceAll();\
        })();";
    view! { cx => <script>(Unescaped::new_unchecked(JS))</script> }
}
