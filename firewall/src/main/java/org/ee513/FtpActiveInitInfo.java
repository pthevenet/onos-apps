package org.ee513;

public class FtpActiveInitInfo {
    private long serverIp;
    private long clientIp;
    private int clientPort;
    private boolean validated;

    public FtpActiveInitInfo(long serverIp, long clientIp, int clientPort) {
        this.serverIp = serverIp;
        this.clientIp = clientIp;
        this.clientPort = clientPort;
        this.validated = false;
    }

    public boolean ipCorresponds(long sIp, long cIp) {
        return (this.serverIp == sIp && this.clientIp == cIp);
    }

    public void validate() {
        this.validated = true;
    }

    public boolean isValidated() {
        return this.validated;
    }


    @Override
    public boolean equals(Object v) {
        boolean r = false;

        if (v instanceof FtpActiveInitInfo){
            FtpActiveInitInfo n = (FtpActiveInitInfo) v;
            r = (this.serverIp == n.serverIp && this.clientIp == n.clientIp && this.clientPort == n.clientPort && this.validated == n.validated);
        }

        return r;
    }

    @Override
    public int hashCode() {
        int hash = (int) (clientPort + clientIp * 10 + serverIp * 100);
        return hash;
    }

    @Override
    public String toString() {
        return "" + this.serverIp + "/" + this.clientIp + ":" + this.clientPort + " " + validated;
    }
}