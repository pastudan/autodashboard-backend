import os from "os";

// Function to check if an IP is within a range
export function isIpInRange(ip, rangeStart, rangeEnd) {
  const [ip1, ip2, ip3, ip4] = ip.split(".").map(Number);
  const [rangeStart1, rangeStart2, rangeStart3, rangeStart4] = rangeStart
    .split(".")
    .map(Number);
  const [rangeEnd1, rangeEnd2, rangeEnd3, rangeEnd4] = rangeEnd
    .split(".")
    .map(Number);

  return (
    (ip1 > rangeStart1 ||
      (ip1 === rangeStart1 &&
        (ip2 > rangeStart2 ||
          (ip2 === rangeStart2 &&
            (ip3 > rangeStart3 ||
              (ip3 === rangeStart3 && ip4 >= rangeStart4)))))) &&
    (ip1 < rangeEnd1 ||
      (ip1 === rangeEnd1 &&
        (ip2 < rangeEnd2 ||
          (ip2 === rangeEnd2 &&
            (ip3 < rangeEnd3 || (ip3 === rangeEnd3 && ip4 <= rangeEnd4))))))
  );
}

export function getInterfaceInfo() {
  // Get the network interfaces
  const interfaces = os.networkInterfaces();
  // Check all network interfaces
  for (const iface of Object.values(interfaces)) {
    for (const info of iface) {
      if (!info.internal && info.family === "IPv4") {
        const ip = info.address;
        // Check if the IP is in one of the private ranges
        if (
          isIpInRange(ip, "10.0.0.0", "10.255.255.255") ||
          isIpInRange(ip, "172.16.0.0", "172.31.255.255") ||
          isIpInRange(ip, "192.168.0.0", "192.168.255.255")
        ) {
          return info;
        }
      }
    }
    // throw new Error("Could not find a private IP address");
  }
}
