// Taint flow patterns: callbacks, loops, sanitizers

function forEachTaint(req, res) {
    const items = req.body.items;
    items.forEach(item => {
        res.send("<div>" + item + "</div>");
    });
}

function mapTaint(req, res) {
    const names = req.query.names;
    const html = names.map(name => "<li>" + name + "</li>");
    res.send(html.join(""));
}

function mapSanitized(req, res) {
    const names = req.query.names;
    const html = names.map(name => "<li>" + escapeHtml(name) + "</li>");
    res.send(html.join(""));
}

function forOfTaint(req, res) {
    const entries = req.body.entries;
    for (const entry of entries) {
        eval(entry);
    }
}

function forOfDestructure(req, res) {
    const entries = req.body.entries;
    for (const { key, value } of entries) {
        res.send(key + "=" + value);
    }
}

function templateSink(req, res) {
    const name = req.query.name;
    document.getElementById("out").innerHTML = `<h1>${name}</h1>`;
}

function noTaint() {
    const items = ["safe", "values"];
    items.forEach(item => {
        console.log(item);
    });
}

function filterTaint(req, res) {
    const users = req.body.users;
    const active = users.filter(u => u.active);
    res.json(active);
}
