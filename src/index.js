const express = require("express");

const app = express();

app.use(express.json());

require("dotenv").config();

const whois = require("whois");
const dns = require("dns");
const axios = require("axios");

const util = require("util");
const client = require("shodan-client");

app.get("/", (req, res) => {
  res.send("Hello World!");
});

const parseWHOIS = (data) => {
  const lines = data.split("\n").filter((line) => line.trim() !== "");
  const result = {};
  lines.forEach((line) => {
    const parts = line.split(": ");
    if (parts.length > 1) {
      const key = parts[0].trim();
      const value = parts.slice(1).join(": ").trim();
      if (result[key]) {
        if (Array.isArray(result[key])) {
          result[key].push(value);
        } else {
          result[key] = [result[key], value];
        }
      } else {
        result[key] = value;
      }
    }
  });
  return result;
};

app.post("/getURLData", async (req, res) => {
  const { link } = req.body;
  // what we want is:
  // where to get these data?
  // ip address can be found by dns.lookup
  // domain age can be found by whois
  // http/https can be found by checking the url
  // certificate validity can be found by checking the url
  // last analysis date can be found by checking the url
  // virus total analysis can be found by checking the url
  // reputation can be found by checking the url

  // let us start with these first
  // to get the data we need to use the following libraries
  // dns.lookup
  // whois
  // axios
  // we can use axios to get the data from the url
  // we can use dns.lookup to get the ip address
  // we can use whois to get the domain age

  // code to get the ip address from famil 4 i.e only ipv4
  let ipAdrr = "";
  dns.lookup(link, { family: 4 }, (err, address, family) => {
    console.log("address: %j family: IPv%s", address, family);
    ipAdrr = address;
  });

  // code to get the whois data
  const whoisResponse = await util.promisify(whois.lookup)(link);
  const whoisData = parseWHOIS(whoisResponse);

  // how to get asn?
  // asn can be found by using the ip address
  // we can use the following api to get the asn
  // https://ipinfo.io/
  // we can use axios to get the data from the api
  // write code below

  // code to get the asn
  const ipinfoResponse = await axios.get(`https://ipinfo.io/${ipAdrr}/json`);
  const ipinfoData = await ipinfoResponse.data;

  // to get domainAge we can use the whois data
  // we can use the following code to get the domain age
  // write code below

  // ports we can get from shodan api
  // https://api.shodan.io/shodan/host
  // we can use axios to get the data from the api
  // write code below

  const portList = await client.ports(process.env.SHODAN_API_KEY);

  // security analysis we can get from virustotal api
  // https://www.virustotal.com/gui/home/upload

  console.log(whoisData);

  const fakeData = {
    url: {
      url: whoisData["Domain Name"],
      ipAddress: ipinfoData.ip,
      asn: ipinfoData.org,
      geolocation:
        ipinfoData.country + ", " + ipinfoData.region + ", " + ipinfoData.city,
      domainAge: whoisData["Creation Date"],
      httpHttps: "HTTPS",
      certificateValidity: "Valid until 2024-09-13",
      lastAnalysisDate: new Date(),
      virusTotalAnalysis: "No Malicious Content Detected",
      reputation: "Neutral",
    },
    domain: {
      registrar: whoisData["Registrar"],
      whoisRegistrantInfo: whoisData["Registrant WHOIS Server"],
      whoisAdminContact: whoisData["Admin Email"],
      whoisAbuseContact: whoisData["Registrar Abuse Contact Email"],
      domainCreationDate: whoisData["Creation Date"],
      domainExpirationDate: whoisData["Registrar Registration Expiration Date"],
      whoisAvailability: whoisData["Registrar"] ? "Available" : "Not Available",
    },
    ip: {
      ipAddress: ipinfoData.ip,
      isp: ipinfoData.org,
      region: ipinfoData.region,
      portScan: "No open malicious ports detected",
      threatsDetected: "None",
    },
    securityAnalysis: [
      {
        engine: "Viettel Threat Intelligence",
        category: "Blacklist",
        result: "Undetected",
        status: "Caution",
      },
      {
        engine: "VIPRE",
        category: "Blacklist",
        result: "Undetected",
        status: "Caution",
      },
      {
        engine: "Webroot",
        category: "Blacklist",
        result: "Undetected",
        status: "Caution",
      },
      {
        engine: "ZeroCERT",
        category: "Blacklist",
        result: "Undetected",
        status: "Caution",
      },
      {
        engine: "Zvelo",
        category: "Blacklist",
        result: "Undetected",
        status: "Caution",
      },
      {
        engine: "Xcitium Verdict Cloud",
        category: "Blacklist",
        result: "Undetected",
        status: "Caution",
      },
      {
        engine: "VirusTotal Results",
        category: "Clean",
        result: "Undetected",
        status: "Clean",
      },
    ],
    ports: [
      {
        port: 80,
        service: "HTTP",
        status: "Active",
        riskLevel: "Low Risk",
      },
      {
        port: 443,
        service: "HTTPS",
        status: "Active",
        riskLevel: "Secure",
      },
      {
        port: 21,
        service: "FTP",
        status: "Inactive",
        riskLevel: "Safe",
      },
      {
        port: 22,
        service: "SSH",
        status: "Active",
        riskLevel: "Risky",
      },
    ],
    protocols: [
      {
        protocol: "TLS 1.2",
        status: "Active",
        securityRating: "Secure",
        recommendation: "None",
      },
      {
        protocol: "TLS 1.0",
        status: "Inactive",
        securityRating: "Weak",
        recommendation: "Upgrade to TLS 1.2",
      },
      {
        protocol: "SSH",
        status: "Active",
        securityRating: "Risky",
        recommendation: "Close/Limit Access",
      },
    ],
  };

  res.status(200).json(fakeData);
});

app.listen(3000, () => {
  console.log("Server is running on http://localhost:3000");
});

// Run the server
