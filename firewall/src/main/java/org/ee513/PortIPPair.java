package org.ee513;

public class PortIPPair {
    private long ip;
    private int port;

    public PortIPPair(long ip, int port) {
        this.ip = ip;
        this.port = port;
    }

    public long getIp() {
        return ip;
    }
    public int getPort() {
        return port;
    }

    public boolean corresponds(PortIPPair p) {
        if (p.getIp() == ip || p.ip == 0 || ip == 0) {
            // ips match
            if (port == p.getPort() || port == 0 || p.getPort() == 0) {
                return true;
            }
        }
        return false;
    }

    @Override
    public String toString() {
        return "" + ip + ":" + port;
    }
}