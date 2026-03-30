function vulnerableXss(req, res) {
    const userInput = req.query.name;
    const html = "<h1>" + userInput + "</h1>";
    res.send(html);
}

function sanitizedXss(req, res) {
    const userInput = req.query.name;
    const safe = escapeHtml(userInput);
    const html = "<h1>" + safe + "</h1>";
    res.send(html);
}

function multilineCall(req, res) {
    const userInput = req.query.search;
    const result = fetch(
        "/api/search?q=" + userInput,
        { method: "GET" }
    );
}
