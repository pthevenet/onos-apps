package org.ee513;

public class Entry {
    private PortIPPair p1;
    private PortIPPair p2;

    public Entry(PortIPPair p1, PortIPPair p2) {
        this.p1 = new PortIPPair(p1.getIp(), p1.getPort());
        this.p2 = new PortIPPair(p2.getIp(), p2.getPort());
    }

    public Entry(long ip1, int port1, long ip2, int port2) {
        this(new PortIPPair(ip1, port1), new PortIPPair(ip2, port2));
    }

    public PortIPPair getPair1() {
        return new PortIPPair(p1.getIp(), p1.getPort());
    }
    public PortIPPair getPair2() {
        return new PortIPPair(p2.getIp(), p2.getPort());
    }

    public boolean corresponds(Entry e) {
        if (p1.corresponds(e.getPair1()) && p2.corresponds(e.getPair2())) {
            return true;
        } else if (p2.corresponds(e.getPair1()) && p1.corresponds(e.getPair2())) {
            return true;
        } else {
            return false;
        }
    }

    @Override
    public boolean equals(Object obj) {
        if (!(obj instanceof Entry)) {
            return false;
        }

        return this.corresponds((Entry) obj);
    }

    @Override
    public int hashCode() {
        return (int) ((p1.getIp() + p2.getIp()) * (p1.getPort() + p2.getPort()));
    }

    @Override
    public String toString() {
        return p1.toString() + "|" + p2.toString();
    }
}