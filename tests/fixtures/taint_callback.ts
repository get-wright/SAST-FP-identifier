// TypeScript taint patterns

async function asyncForEachTaint(req: Request) {
    const items: string[] = req.body.items;
    items.forEach(async (item: string) => {
        await db.query(`SELECT * FROM t WHERE name = '${item}'`);
    });
}

function reduceTaint(req: Request) {
    const parts: string[] = req.query.parts;
    const combined = parts.reduce((acc, part) => acc + part, "");
    eval(combined);
}

function typedForOf(req: Request) {
    const entries: Array<{key: string, value: string}> = req.body.entries;
    for (const { key, value } of entries) {
        document.getElementById(key)!.innerHTML = value;
    }
}

function logTaint(settings: RemoteSetting[]) {
    for (const setting of settings) {
        const key = setting.settingKey;
        console.log(`[Sync] Updating setting: ${key}`);
    }
}
