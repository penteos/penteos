export async function activate(plugin) {
  plugin.operation("run", async (input, penteos) => {
    const r = await penteos.http({ url: "https://api.contract.test/thing", headers: { "X-Key": "{{settings.key}}" } });
    const put = await penteos.graph.put("thing", { name: input.name + ":" + r.body.ok });
    const got = await penteos.graph.get(put.id);
    await penteos.store.insert("log", { text: "ran" });
    const rows = await penteos.store.query("log");
    const settings = await penteos.settings();
    penteos.log("contract ran");
    return { thing: got.attributes.name, rows: rows.length, settingsSeen: Object.keys(settings) };
  });
  plugin.operation("parse", async (input) => ({ items: String(input.text).split("\n").slice(1).filter(Boolean).map((ip) => ({ op: "upsert", kind: "host", key: { ip: ip.trim() } })) }));
}
