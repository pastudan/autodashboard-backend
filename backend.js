import { exec } from "child_process";
import { promisify } from "util";
import { parseString } from "xml2js";
import { readFile, writeFile } from "fs/promises";
import fetch from "node-fetch";
import { getInterfaceInfo } from "./functions.js";
import { WebSocketServer } from "ws";

let hosts = [];
let services = [];

const wss = new WebSocketServer({ port: 8181 });
wss.on("connection", function connection(socket) {
  socket.on("message", function incoming(message) {
    console.log("[WebSocketServer]: %s", message);
    wss.clients.forEach((client) => {
      client.send(message.toString());
    });
  });
  sendWsMessage("hosts", hosts);
  // console.log("[WebSocketServer] New socket connected!");
});
function sendWsMessage(type, payload) {
  wss.clients.forEach((client) => {
    client.send(JSON.stringify({ type, payload }));
  });
}

const execAsync = promisify(exec);
const parseStringAsync = promisify(parseString);

async function loadOui() {
  // download wireshark OUI db file if not exists
  let oui;
  try {
    oui = await readFile("oui.txt", "utf8");
  } catch (e) {}
  if (!oui) {
    const ouiRes = await fetch(
      "https://www.wireshark.org/download/automated/data/manuf"
    );
    oui = await ouiRes.text();
    await writeFile("oui.txt", oui);
  }
  oui = oui
    .split("\n")
    .filter((line) => !line.startsWith("#"))
    .map((line) => {
      const [mac, _shortVendor, vendor] = line.split("\t").map((s) => s.trim());
      return { mac, vendor: vendor?.split(" ")[0] };
    }); // TODO handle blocks like /24
  return oui;
}

async function mapHosts() {
  const iface = getInterfaceInfo();
  function macToVendor(mac) {
    mac = mac?.toUpperCase();
    return oui.find((o) => mac?.startsWith(o.mac))?.vendor || null;
  }
  hosts = [
    {
      ip: iface.address,
      mac: iface.mac.toUpperCase(),
      vendor: macToVendor(iface.mac),
    },
  ];
  console.log(`Scanning ${iface.cidr} using nmap...`);
  const { stdout } = await execAsync(`nmap -sn ${iface.cidr} -oX -`);
  const result = await parseStringAsync(stdout);
  result.nmaprun.host.forEach((host) => {
    const ip = host.address.find((a) => a?.$?.addrtype === "ipv4")?.$?.addr;
    const mac = host.address.find((a) => a?.$?.addrtype === "mac")?.$?.addr;
    if (ip === iface.address) return;
    hosts.push({
      ip,
      mac,
      vendor: macToVendor(mac),
    });
  });
  hosts = hosts.sort((a, b) => (a.vendor > b.vendor ? 1 : -1));
  console.table(hosts);
  sendWsMessage("hosts", hosts);
  writeFile("hosts.json", JSON.stringify(hosts, null, 2));
}

async function serviceDiscovery() {
  console.log(`Scanning for services using avahi-browse...`);
  const { stdout } = await execAsync(
    `avahi-browse --all --terminate --resolve --parsable`
  );
  const lines = stdout.split("\n");
  services = lines
    .map((line) => {
      const parts = line.split(";");
      const protocol = parts[2];
      if (protocol !== "IPv4") return;
      return {
        type: parts[0],
        iface: parts[1],
        protocol: parts[2],
        name: parts[3],
        record: parts[4],
        domain: parts[5],
        hostname: parts[6],
        ip: parts[7],
        port: parts[8],
        attributes: parts[9],
      };
    })
    .filter(Boolean);
  // console.table(services);
  hosts = hosts.map((host) => {
    const deviceServices = services.filter((s) => s.ip === host.ip);
    let deviceType = "Unknown";
    deviceServices.forEach((s) => {
      deviceType =
        recordRegex.find((r) => r.regex.test(s.record))?.name ||
        kvRegex.find((r) => r.regex.test(s.attributes))?.name ||
        hostnameRegex.find((r) => r.regex.test(s.hostname))?.name ||
        "Unknown";
    });
    // if (host.ip === "10.9.6.36") console.log(deviceServices);
    return {
      ...host,
      // services: deviceServices,
      deviceType,
    };
  });

  console.table(hosts);
  sendWsMessage("hosts", hosts);
}

const recordRegex = [
  { regex: /_amzn-alexa._tcp/, name: "Alexa" },
  { regex: /Amazon Fire TV/, name: "Fire TV" },
];
const kvRegex = [
  { regex: /"md=Google Nest Hub"/, name: "Nest Hub" },
  { regex: /"md=BSB002"/, name: "Hue Hub" },
  { regex: /=AppleTV/, name: "TV" },
];
const hostnameRegex = [{ regex: /-MacBook-/, name: "MacBook" }];

const oui = await loadOui();
hosts = JSON.parse(await readFile("hosts.json", "utf8"));
await mapHosts();
await serviceDiscovery();
