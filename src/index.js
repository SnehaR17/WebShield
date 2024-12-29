const express = require("express");
const axios = require("axios");
const bodyParser = require("body-parser");
require("dotenv").config();
const util = require("util");
const client = require("shodan-client");
const { asn } = require("shodan-client/lib/streams");

const app = express();

app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(bodyParser.json());

// get URL Report
const getURLReport = async (link) => {
  try {
    const encodedParams = new URLSearchParams();
    encodedParams.set("url", link);

    const options = {
      method: "POST",
      url: "https://www.virustotal.com/api/v3/urls",
      headers: {
        accept: "application/json",
        "x-apikey": process.env.VIRUSTOTAL_API_KEY,
        "content-type": "application/x-www-form-urlencoded",
      },
      data: encodedParams,
    };

    const response = await axios(options);

    const next_options = {
      method: "GET",
      url: "https://www.virustotal.com/api/v3/analyses/u-4d72c171667efe6c719e4b669103d3d909a0c789940a956871644cbb74e89aa1-1735433440",
      headers: {
        accept: "application/json",
        "x-apikey":
          "e7f1f6d694a399486286ee203213077bf4558c04f09ea6ee7a32fdb5ab8bfe66",
      },
    };

    const next_response = await axios(next_options);
    return next_response.data;
  } catch (error) {
    console.log(error);
  }
};
// get IP Address Report
const getIPReport = async () => {
  try {
    const options = {
      method: "GET",
      url: "https://www.virustotal.com/api/v3/ip_addresses/172.67.26.69",
      headers: {
        accept: "application/json",
        "x-apikey": process.env.VIRUSTOTAL_API_KEY,
      },
    };

    const response = await axios(options);
    return response.data;
  } catch (error) {
    console.log(error);
  }
};
// get Domain Report
const getDomainReport = async () => {
  try {
    const options = {
      method: "GET",
      url: "https://www.virustotal.com/api/v3/domains/test.com",
      headers: {
        accept: "application/json",
        "x-apikey": process.env.VIRUSTOTAL_API_KEY,
      },
    };

    const response = await axios(options);
    return response.data;
  } catch (error) {
    console.log(error);
  }
};

// Common and Expected Ports for a Website
// These are typical ports that websites legitimately use:
// Port 80: HTTP (unencrypted web traffic).
// Port 443: HTTPS (encrypted web traffic).
// Port 8080: Alternative HTTP (commonly used for web applications or proxies).
// Port 8443: Alternative HTTPS (commonly used for secure web applications).
// Port 22: SSH (used for server management, not directly web-related but common for hosting).

// Ports Considered Miscellaneous for a Website
// These ports are generally not expected for standard website functionality and may indicate:

// Exposed services unrelated to the website.
// Misconfigurations or forgotten services.
// Potential security risks or malicious intent.
// 1. File Sharing and Data Transfer Ports
// Port 21: FTP (File Transfer Protocol, often unsecured).
// Port 69: TFTP (Trivial File Transfer Protocol, no authentication).
// Port 445: SMB (Server Message Block, used for Windows file sharing).
// 2. Database Ports
// Port 3306: MySQL.
// Port 5432: PostgreSQL.
// Port 1433/1434: Microsoft SQL Server.
// Port 6379: Redis.
// Port 27017: MongoDB.
// Exposing database ports directly is dangerous as they can be targeted by attackers.
// 3. Remote Access Ports
// Port 3389: RDP (Remote Desktop Protocol, for Windows systems).
// Port 5900: VNC (Virtual Network Computing).
// Port 23: Telnet (unencrypted, outdated).
// 4. Email Service Ports
// Port 25: SMTP (commonly blocked to prevent spam).
// Port 110: POP3 (email retrieval).
// Port 143: IMAP (email retrieval).
// 5. Peer-to-Peer and Torrent Ports
// Port 6881–6889: BitTorrent traffic.
// Port 135: RPC (Remote Procedure Call).
// 6. VPN and Proxy Ports
// Port 500: IPSec VPN.
// Port 1701: L2TP VPN.
// Port 1194: OpenVPN.
// 7. Miscellaneous Ports Used by Malware or Hacking Tools
// Port 4444: Commonly associated with Metasploit’s reverse shells.
// Port 5555: Sometimes used by ADB (Android Debug Bridge), exploitable if exposed.
// Port 6667: IRC (Internet Relay Chat, often used for botnets).
// Port 2049: NFS (Network File System).
// Port 8081, 8181: Frequently used by testing servers or forgotten dev setups.
// 8. IoT and Device-Specific Ports
// Port 8000–8090: Frequently used by IoT devices, proxies, or alternative HTTP.
// Port 49152–65535: Dynamic/private ports (often temporary but could indicate misconfigurations).

const averagePorts = [
  80, // HTTP (Standard web traffic)
  443, // HTTPS (Encrypted web traffic)
  8080, // Alternative HTTP (Proxies, testing)
  8443, // Alternative HTTPS
  22, // SSH (Server management)
  21, // FTP (File Transfer, often legacy)
  53, // DNS (if the server handles its own domain resolution)
  25, // SMTP (Email sending, often blocked)
  110, // POP3 (Legacy email retrieval)
  143, // IMAP (Modern email retrieval)
];

const miscellaneousPorts = [
  // Vulnerable database ports
  3306, // MySQL
  5432, // PostgreSQL
  1433, // Microsoft SQL Server
  27017, // MongoDB
  6379, // Redis

  // Remote access ports
  23, // Telnet (Unencrypted, legacy)
  3389, // RDP (Windows Remote Desktop Protocol)
  5900, // VNC (Virtual Network Computing)

  // P2P and torrent-related ports
  6881, // BitTorrent traffic
  6667, // IRC (Often used by botnets)

  // Miscellaneous risky ports
  2049, // NFS (Network File System)
  5555, // ADB (Android Debug Bridge, often exploitable)
  4444, // Metasploit reverse shell
  8081, // Commonly used for dev testing servers
  8181, // Miscellaneous HTTP servers

  // IoT and dynamic ports
  49152, // Random dynamic port (IoT and UPnP usage)
  65535, // Upper boundary of dynamic port range
];

// get Shodan Report
const getShodanReport = async () => {
  try {
    const presentPorts = await client.ports(process.env.SHODAN_API_KEY);

    // check if the ports are in averagePorts or miscellaneousPorts
    // if they are in averagePorts, then they are legitimate ports
    // if they are in miscellaneousPorts, then they are risky ports
    // if they are not in any of the above, then they are unknown ports
    // send response accordingly

    let legitimatePorts = [];
    let riskyPorts = [];

    presentPorts.forEach((port) => {
      if (averagePorts.includes(port)) {
        legitimatePorts.push(port);
      } else if (miscellaneousPorts.includes(port)) {
        riskyPorts.push(port);
      }
    });

    return {
      legitimatePorts,
      riskyPorts,
    };
  } catch (error) {
    console.log(error);
  }
};

app.get("/", (req, res) => {
  res.status(200).send("Hello World");
});

// 1. accept a GET request at /search that takes a link of website as a req.body
//  this search will do several operations:
// 1.1 check if the website exists in public Threat Databases (eg PhishTank)
// 1.2 collect data from External APIs (eg Shodan, Censys)
// 1.3 Domain Analysis (eg Whois, DNS Lookup, Subdomain Check, SSL Information, Trade Route, Deep Packet Inspecion, WAF Check)
// 1.4 Send all the data recieved from 1.2 and 1.3 to the LLM Model and collect inferences along with metadata and then store all data in the MongoDB Database

app.post("/search", async (req, res) => {
  // get the link from the request
  const { link } = req.body;

  // check if the website exists in public Threat Databases
  const urlReport = await getURLReport(link);
  const ipReport = await getIPReport();
  const domainReport = await getDomainReport();
  const shodanReport = await getShodanReport();

  const sslInfoReq = await axios.get(
    `https://ssl-checker.io/api/v1/check/${link}`
  );

  const sslInfo = await sslInfoReq.data;

  const time = new Date();

  const urlData = {
    url: link ?? "Not Found",
    ipAddress: ipReport.data.id ?? "Not Found",
    as_number:
      ipReport.data.attributes.asn + " " + ipReport.data.attributes.as_owner ??
      "Not Found",
    // geolocation: domainReport.data.attributes.issuer["C"] ?? "Not Found",
    domainAge: domainReport.data.attributes.creation_date ?? "Not Found",
    httpsCert: sslInfo.result.cert_valid
      ? "Valid HTTPS"
      : "HTTP" ?? "Not Found",
    certificateValidity: sslInfo.result.valid_till ?? "Not Found",
    lastAnalysisDate: time.getDate() ?? "Not Found",
    // virusTotalAnalysis,
    // reputation,
  };

  const data = domainReport.data.attributes.whois;
  const lines = data.split("\n");
  const result = {};

  lines.forEach((line) => {
    const [key, value] = line.split(": ").map((str) => str.trim());
    if (key && value) {
      if (result[key]) {
        // If key already exists, store multiple values in an array
        result[key] = Array.isArray(result[key])
          ? result[key].concat(value)
          : [result[key], value];
      } else {
        result[key] = value;
      }
    }
  });

  console.log(result);

  const domainData = {
    registrar: result.Registrar,
    whoisRegistrantInfo: result["Registry Domain ID"] ?? "Not Found",
    whoisAdminContact: result["Registrar Abuse Contact Email"] ?? "Not Found",
    whoisAbuseContact: result["Registrar Abuse Contact Email"] ?? "Not Found",
    domainCreationDate: result["Creation Date"] ?? "Not Found",
    domainExpirationDate: result["Registry Expiry Date"] ?? "Not Found",
    whoisAvailable: result ? "Yes" : "No",
  };

  const ipData = {
    ip: ipReport.data.id ?? "Not Found",
    country: result["Admin Country"] ?? "Not Found",
    city: result["Admin City"] ?? "Not Found",
    isp: ipReport.data.attributes.isp ?? "Not Found",
    organization: ipReport.data.attributes.organization ?? "Not Found",
    lastAnalysisDate: time.getDate() ?? "Not Found",
  };

  res.status(200).json({
    urlReport,
    ipReport,
    domainReport,
    shodanReport,
  });
});

app.post('/getSecurityAnalysis', async (req, res) => {
  const { link } = req.body;
  const urlReport = await getURLReport(link);
  const engineArray = await urlReport.data.attributes.results;

  console.log(engineArray)
})

app.listen(3000, () => {
  console.log("Server is running on port 3000");
});
